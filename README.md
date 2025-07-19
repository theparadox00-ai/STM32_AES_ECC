# STM32_AES_ECC
This project introduces a comprehensive and highly secure embedded communication system based on the STM32G4 microcontroller platform, designed to address the critical need for secure data exchange in resource-constrained environments. 
# STM32 + ATECC608B Secure RNG Demo

A simple STM32 firmware example that reads a 32-byte secure random number from Microchip’s ATECC608B over I²C, and also initializes the STM32's internal hardware RNG. Outputs results via UART for easy testing.

---

## Features

- Secure RNG using **ATECC608B** (via `cryptoauthlib`)
- STM32 onboard **RNG** initialization
- UART debug output at **115200 baud**
- Proper error handling with `Error_Handler()`

---

## Hardware

- STM32 microcontroller with:
  - I²C1, RNG, USART1 (or USART2)
- ATECC608B crypto chip connected to I²C1
- UART‑to‑USB adapter for serial output

---

## Software

- STM32CubeIDE (or CubeMX + GCC/Make)
- STM32 HAL drivers
- Microchip **cryptoauthlib**
- Git for version control

---

## Setup & Build

1. **Clone the repo**  
   ```bash
   git clone https://github.com/yourusername/STM32-ATECC608B-demo.git
   cd STM32-ATECC608B-demo
