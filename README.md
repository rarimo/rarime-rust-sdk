## Rarimo Rust SDK

**A cross-platform SDK written in Rust for seamless and efficient interaction with the Rarimo protocol.**

Our mission is to provide developers with a **single, reliable, and high-performance tool** for integrating with the
Rarimo ecosystem on any platform.  
The SDK is completely **free**, **open-source**, and **community-driven**.

---

## ✨ Key Features

- **Cross-Platform**  
  Built from a single Rust codebase that compiles to native binaries across platforms for maximum portability and
  performance.

- **Performance & Safety**  
  Core cryptographic and protocol logic are implemented in Rust, ensuring memory safety and high-speed execution.

- **Simple & Intuitive API**  
  Complex protocol details are abstracted away, giving developers a clean and ergonomic interface.

- **Modern Tooling**  
  Powered by Mozilla’s [UniFFI](https://mozilla.github.io/uniffi-rs/), enabling type-safe and reliable bindings across
  platforms.

- **Open Source**  
  Fully transparent and open to contributions, improvements, and extensions by the community.

---

## 🏷️️ Architecture

At the heart of the SDK is a **core Rust library** that implements all logic required for interacting with the Rarimo
protocol.

Using **UniFFI**, we define the SDK’s interface in a `.udl` file (`src/rarime.udl`) and automatically generate FFI
bindings for supported platforms.

This architecture allows us to:

- Write and test complex logic **once**, in Rust
- Expose a **native and idiomatic API** to every platform
- Easily extend support for new platforms in the future

---

## 📦 Getting Started

### Prerequisites

- [Rust Toolchain](https://rustup.rs/)
- [UniFFI CLI](https://mozilla.github.io/uniffi-rs/)

Install UniFFI:

```bash
cargo install uniffi_bindgen --version <USED_VERSION>
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/rarimo/rarime-rust-sdk.git
cd rarime-rust-sdk

# Build the Rust library
cargo build --release

# Install UniFFI for generating bindings
cargo install uniffi --features cli

# Generate FFI bindings (example)
uniffi-bindgen generate ./rarime_rust_sdk.udl --language <target_language> --out-dir <output_dir>
```

> 🧠 The SDK’s core is fully portable — you can integrate it with any language or platform supported by UniFFI.

---

## 🚀 Example Usage

```Kotlin
    ///Setup utils
    val utils = RarimeUtils()

    ///Setup Config
    val userPrivateKey = utils.generateBjjPrivateKey()
    val userConfiguration = RarimeUserConfiguration(
        userPrivateKey = userPrivateKey
    )

    val apiConfiguration = RarimeApiConfiguration(
        jsonRpcEvmUrl = "<YOUR_JSON_RPC_URL>",
        rarimeApiUrl = "<YOUR_API_URL>"
    )

    val confContract = RarimeContractsConfiguration(
        stateKeeperContractAddress = "<YOUR_STATE_KEEPER_CONTRACT_ADDRESS>",
         registerContractAddress = "<YOUR_REGISTER_CONTRACT_ADDRESS>"
    )

    val rarimeConfiguration = RarimeConfiguration(
        contractsConfiguration = confContract,
        apiConfiguration = apiConfiguration,
        userConfiguration = userConfiguration
    )

    ///Setup SDK
    val rarime = Rarime(config = rarimeConfiguration)

    ///Setup passport
    val passport = RarimePassport(
        dataGroup1 = emptyList(),
        dataGroup15 = null,
        aaSignature = null,
        aaChallenge = null,
        sod = emptyList()
    )

    ///Check passport status
    ///Status may be :
    ///    NOT_REGISTERED, // not register document
    ///    REGISTERED_WITH_THIS_PK, // document was register with this user private key
    ///    REGISTERED_WITH_OTHER_PK; // document was register with another user private key
    val documentStatus = runBlocking { rarime.getDocumentStatus(passport) }

    ///Light registration
    ///Returned hash of register transaction from blockchain
    val tx_hash = runBlocking { rarime.lightRegistration(passport) }

```

---

## 🤝 Contributing

We welcome and appreciate all contributions!

1. **Fork** the repository
2. **Create** a new branch
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Commit** your changes
   ```bash
   git commit -m "Your awesome commit name"
   ```
4. **Push** your branch
   ```bash
   git push origin feature/your-feature-name
   ```
5. **Open a Pull Request**

Before submitting a PR, please ensure:

- Your code follows the project’s style guidelines
- All tests and builds pass successfully
- No lint warning

---

## 📜 License

This project is distributed under the **MIT License**.  
See the [LICENSE](./LICENSE) file for full details.

---

## 💬 Community

We encourage open collaboration — discussions, suggestions, and feedback are always welcome!  
Join us in improving the Rust ecosystem around the Rarimo protocol.

**Telegram:** [Join Rarimo Community](https://t.me/+pWugh5xgDiE3Y2Jk)
