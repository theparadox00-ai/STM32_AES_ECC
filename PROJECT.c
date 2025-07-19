#include "main.h"
#include "stm32g4xx_hal.h"
#include <string.h>
#include <atca_config.h>
#include <cryptoauthlib.h>
#include <atca_status.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>

// Handles for peripherals
I2C_HandleTypeDef hi2c1;
UART_HandleTypeDef huart1; // Console (Putty etc)
UART_HandleTypeDef huart2; // SATCOM
RNG_HandleTypeDef hrng; // random number hrng (hardware random number generation)

// Constants
#define PUB_KEY_SIZE       64
#define AES_KEY_SIZE       16
#define AES_IV_SIZE        12
#define AES_TAG_SIZE       16
#define SIGNATURE_SIZE     64
#define RX_BUFFER_SIZE     128
#define CHALLENGE_SIZE     32
#define MAX_RETRIES        3
#define COMM_TIMEOUT_MS    5000

// Secure Element key slots
#define DEVICE_KEY_SLOT     0
#define PEER_PUBKEY_SLOT    1

// Buffers
uint8_t device_pubkey[PUB_KEY_SIZE];
uint8_t peer_pubkey[PUB_KEY_SIZE];
uint8_t aes_key[AES_KEY_SIZE];
uint8_t rx_buffer[RX_BUFFER_SIZE];
uint8_t iv[AES_IV_SIZE];
uint8_t challenge[CHALLENGE_SIZE];
uint8_t peer_challenge[CHALLENGE_SIZE];

// ATECC608B configuration over I2C
ATCAIfaceCfg cfg_atecc608b_i2c = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC608B,
    .atcai2c.address = 0xC0,
    .atcai2c.bus = 1,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20
};

// Function prototypes
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_I2C1_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_RNG_Init(void);
void Error_Handler(void);

int generate_and_store_keypair(void) {
    return atcab_genkey(DEVICE_KEY_SLOT, device_pubkey);
}

int receive_data(uint8_t *buf, uint16_t len) {
    return (HAL_UART_Receive(&huart2, buf, len, COMM_TIMEOUT_MS) == HAL_OK) ? ATCA_SUCCESS : ATCA_RX_FAIL;
}

int send_data(uint8_t *buf, uint16_t len) {
    return (HAL_UART_Transmit(&huart2, buf, len, COMM_TIMEOUT_MS) == HAL_OK) ? ATCA_SUCCESS : ATCA_TX_FAIL;
}

int derive_shared_secret(void) {
    uint8_t shared_secret[32];
    ATCA_STATUS status = atcab_ecdh(DEVICE_KEY_SLOT, peer_pubkey, shared_secret);
    if (status != ATCA_SUCCESS) {
    	return status;
    }

    wc_Sha256 sha;
    uint8_t hash[32];
    if (wc_InitSha256(&sha) != 0) {
    	return ATCA_GEN_FAIL;
    }
    if (wc_Sha256Update(&sha, shared_secret, sizeof(shared_secret))) {
    	return ATCA_GEN_FAIL;
    }
    if (wc_Sha256Final(&sha, hash)) {
    	return ATCA_GEN_FAIL;
    }

    memcpy(aes_key, hash, AES_KEY_SIZE);
    return ATCA_SUCCESS;
}

void generate_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t rnd;
        HAL_RNG_GenerateRandomNumber(&hrng, &rnd);
        memcpy(&buf[i], &rnd, (len - i >= 4) ? 4 : len - i);
    }
}

int encrypt_message(const uint8_t *plaintext, uint32_t length, uint8_t *ciphertext, uint8_t *tag) {
    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID)) {
    	return -1;
    }
    if (wc_AesGcmSetKey(&aes, aes_key, AES_KEY_SIZE)) {
        wc_AesFree(&aes);
        return -1;
    }
    int ret = wc_AesGcmEncrypt(&aes, ciphertext, plaintext, length, iv, AES_IV_SIZE, tag, AES_TAG_SIZE, NULL, 0);
    wc_AesFree(&aes);
    return ret;
}

int sign_message(const uint8_t *msg, size_t msg_len, uint8_t *signature) {
    uint8_t hash[32];
    wc_Sha256 sha;

    if (wc_InitSha256(&sha)){
    	return ATCA_GEN_FAIL;
    }
    if (wc_Sha256Update(&sha, msg, msg_len)){
    	return ATCA_GEN_FAIL;
    }
    if (wc_Sha256Final(&sha, hash)){
    	return ATCA_GEN_FAIL;
    }

    return atcab_sign(DEVICE_KEY_SLOT, hash, signature);
}

int verify_peer_public_key(void) {
    uint8_t peer_signature[SIGNATURE_SIZE];
    if (receive_data(peer_signature, SIGNATURE_SIZE) != ATCA_SUCCESS) return ATCA_RX_FAIL;

    uint8_t hash[32];
    wc_Sha256 sha;
    if (wc_InitSha256(&sha)) {
    	return ATCA_GEN_FAIL;
    }
    if (wc_Sha256Update(&sha, challenge, CHALLENGE_SIZE)) {
    	return ATCA_GEN_FAIL;
    }
    if (wc_Sha256Final(&sha, hash)){
    	return ATCA_GEN_FAIL;
    }

    ecc_key key;
    wc_ecc_init(&key);
    if (wc_ecc_import_x963(peer_pubkey, PUB_KEY_SIZE, &key) != 0) {
        wc_ecc_free(&key);
        return ATCA_FUNC_FAIL;
    }
    if (wc_ecc_set_curve(&key, 32, ECC_SECP256R1) != 0) {
        wc_ecc_free(&key);
        return ATCA_FUNC_FAIL;
    }

    int verify_res = 0;
    int ret = wc_ecc_verify_hash(peer_signature, SIGNATURE_SIZE, hash, sizeof(hash), &verify_res, &key);
    wc_ecc_free(&key);

    return (ret == 0 && verify_res == 1) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

int perform_key_exchange(void) {
    if (send_data(device_pubkey, PUB_KEY_SIZE) != ATCA_SUCCESS) {
    	return ATCA_TX_FAIL;
    }
    if (receive_data(peer_pubkey, PUB_KEY_SIZE) != ATCA_SUCCESS) {
    	return ATCA_RX_FAIL;
    }

    generate_random(challenge, CHALLENGE_SIZE);
    if (send_data(challenge, CHALLENGE_SIZE) != ATCA_SUCCESS) {
    	return ATCA_TX_FAIL;
    }
    if (verify_peer_public_key() != ATCA_SUCCESS) {
    	return ATCA_FUNC_FAIL;
    }

    if (receive_data(peer_challenge, CHALLENGE_SIZE) != ATCA_SUCCESS) {
    	return ATCA_RX_FAIL;
    }
    uint8_t signature[SIGNATURE_SIZE];
    if (sign_message(peer_challenge, CHALLENGE_SIZE, signature) != ATCA_SUCCESS) {
    	return ATCA_GEN_FAIL;
    }
    if (send_data(signature, SIGNATURE_SIZE) != ATCA_SUCCESS) {
    	return ATCA_TX_FAIL;
    }

    return derive_shared_secret();
}

int receive_user_input(void) {
    const char *prompt = "Enter message (max 128 chars):\r\n";
    HAL_UART_Transmit(&huart1, (uint8_t*)prompt, strlen(prompt), HAL_MAX_DELAY);

    uint8_t ch;
    uint16_t idx = 0;
    memset(rx_buffer, 0, RX_BUFFER_SIZE);

    while (idx < RX_BUFFER_SIZE - 1) {
        if (HAL_UART_Receive(&huart1, &ch, 1, HAL_MAX_DELAY) != HAL_OK) return -1;
        if (ch == '\r' || ch == '\n') break;

        HAL_UART_Transmit(&huart1, &ch, 1, HAL_MAX_DELAY);
        rx_buffer[idx++] = ch;
    }
    return idx;
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_I2C1_Init();
    MX_USART1_UART_Init();
    MX_USART2_UART_Init();
    MX_RNG_Init();

    if (atcab_init(&cfg_atecc608b_i2c) != ATCA_SUCCESS) {
    	Error_Handler();
    }
    if (generate_and_store_keypair() != ATCA_SUCCESS) {
    	Error_Handler();
    }

    int retries = 0;
    while (perform_key_exchange() != ATCA_SUCCESS) {
        if (++retries >= MAX_RETRIES) {
        	Error_Handler();
        }
        HAL_Delay(1000);
    }

    uint8_t encrypted[RX_BUFFER_SIZE];
    uint8_t tag[AES_TAG_SIZE];

    while (1) {
        int len = receive_user_input();
        if (len <= 0) {
        	continue;
        }

        generate_random(iv, AES_IV_SIZE);

        if (encrypt_message(rx_buffer, len, encrypted, tag) != 0) {
        	Error_Handler();
        }

        if (send_data(iv, AES_IV_SIZE) != ATCA_SUCCESS ||
            send_data(tag, AES_TAG_SIZE) != ATCA_SUCCESS ||
            send_data(encrypted, len) != ATCA_SUCCESS) {
            Error_Handler();
        }

        uint8_t signature[SIGNATURE_SIZE];
        if (sign_message(rx_buffer, len, signature) != ATCA_SUCCESS) {
        	Error_Handler();
        }
        if (send_data(signature, SIGNATURE_SIZE) != ATCA_SUCCESS) {
        	Error_Handler();
        }
    }
}

void SystemClock_Config(void){
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLM = RCC_PLLM_DIV1;
    RCC_OscInitStruct.PLL.PLLN = 12;
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
    RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV4;
    RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
        Error_Handler();
    }
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK| RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK) {
        Error_Handler();
    }
}

static void MX_I2C1_Init(void) {
    hi2c1.Instance = I2C1;
    hi2c1.Init.Timing = 0x00300617;
    hi2c1.Init.OwnAddress1 = 0;
    hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
    hi2c1.Init.OwnAddress2 = 0;
    hi2c1.Init.OwnAddress2Masks = I2C_OA2_NOMASK;
    hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
    if (HAL_I2C_Init(&hi2c1) != HAL_OK) {
        Error_Handler();
    }
    if (HAL_I2CEx_ConfigAnalogFilter(&hi2c1, I2C_ANALOGFILTER_ENABLE) != HAL_OK) {
        Error_Handler();
    }
    if (HAL_I2CEx_ConfigDigitalFilter(&hi2c1, 0) != HAL_OK) {
        Error_Handler();
    }
}

static void MX_RNG_Init(void){
  hrng.Instance = RNG;
  hrng.Init.ClockErrorDetection = RNG_CED_ENABLE;
  if (HAL_RNG_Init(&hrng) != HAL_OK){
    Error_Handler();
  }
}

static void MX_USART1_UART_Init(void){
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK){
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK){
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK){
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK){
    Error_Handler();
  }
}

static void MX_USART2_UART_Init(void){
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.Init.ClockPrescaler = UART_PRESCALER_DIV1;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK){
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart2, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK){
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart2, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK){
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart2) != HAL_OK){
    Error_Handler();
  }
}

static void MX_GPIO_Init(void) {
    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOF_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
}

void Error_Handler(void) {
    __disable_irq();
    while (1) {}
}

#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line) {
    Error_Handler();
}
#endif
