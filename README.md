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

Using **UniFFI**, we define the SDK’s interface in a `.udl` file (`./rarime_rust_sdk.udl`) and automatically generate
FFI
bindings for supported platforms.

This architecture allows us to:

- Write and test complex logic **once**, in Rust
- Expose a **native and idiomatic API** to every platform
- Easily extend support for new platforms in the future

---

## 📦 Getting Started

## 🛠 Build Requirements

To successfully build this SDK, the following tools and versions are required:

- **Standalone Clang version <= 16.0.0**
    - see installation for macOS [click](docs/MacOS-clang-install.md)
- **CMake**
- **Ninja**
- [**Rust Toolchain**](https://rustup.rs/)
- [**UniFFI CLI**](https://mozilla.github.io/uniffi-rs/)

Install UniFFI:

```bash
 cargo install uniffi --version 0.30.0 --features cli
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
> 🔗 For more detailed information about the supported languages and the binding generation process, please visit
> the [UniFFI project page](https://github.com/mozilla/uniffi-rs).

---

# Configuration for integration

We support two chains:

- **MainNet** — for releases and production use
- **TestNet** — for development and testing

> **Note:** You can also use your own addresses and resources.

---

## API Addresses

| Name                 | MainNet Address               | TestNet Address                         |
|----------------------|-------------------------------|-----------------------------------------|
| `JSON_RPC_URL`       | `https://l2.rarimo.com`       | `https://rpc.evm.mainnet.rarimo.com`    |
| `API_URL`            | `https://api.app.rarime.com`  | `https://api.orgs.app.stage.rarime.com` |
| `IPFS_URL`           | `https://ipfs.rarimo.com `    | `https://ipfs.rarimo.com `              |
| `VOTING_RELAYER_URL` | `https://api.freedomtool.org` | `https://api.stage.freedomtool.org`     |
| `FREEDOMTOOL_URL`    | `https://freedomtool.org`     | `https://stage.voting.freedomtool.org/` |
| `VOUTING_RPC_URL`    | `https://l2.rarimo.com`       | `https://rpc.qtestnet.org`              |

---

## Contract Addresses

| Name                              | MainNet Address                              | TestNet Address                              |
|-----------------------------------|----------------------------------------------|----------------------------------------------|
| `STATE_KEEPER_CONTRACT_ADDRESS`   | `0x61aa5b68D811884dA4FEC2De4a7AA0464df166E1` | `0x9EDADB216C1971cf0343b8C687cF76E7102584DB` |
| `REGISTER_CONTRACT_ADDRESS`       | `0x497D6957729d3a39D43843BD27E6cbD12310F273` | `0xd63782478CA40b587785700Ce49248775398b045` |
| `POSEIDON_SMT_ADDRESS`            | `0x479F84502Db545FA8d2275372E0582425204A879` | `0xF19a85B10d705Ed3bAF3c0eCe3E73d8077Bf6481` |
| `PROPOSAL_STATE_CONTRACT_ADDRESS` | `0x9C4b84a940C9D3140a1F40859b3d4367DC8d099a` | `0x4C61d7454653720DAb9e26Ca25dc7B8a5cf7065b` |

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
        jsonRpcEvmUrl = "<JSON_RPC_URL>",
        rarimeApiUrl = "<API_URL>"
    )

    val confContract = RarimeContractsConfiguration(
        stateKeeperContractAddress = "<STATE_KEEPER_CONTRACT_ADDRESS>",
        registerContractAddress = "<REGISTER_CONTRACT_ADDRESS>",
        poseidonSmtAddress = "<POSEIDON_SMT_ADDRESS>"
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

    /**
     * Checks the passport registration status.
     *
     * Possible statuses:
     * - NOT_REGISTERED – the document is not registered.
     * - REGISTERED_WITH_THIS_PK – the document is registered with this user's private key.
     * - REGISTERED_WITH_OTHER_PK – the document is registered with a different user's private key.
     */
    val documentStatus = runBlocking { rarime.getDocumentStatus(passport) }

    ///Light registration
    ///Returned hash of register transaction from blockchain
    val tx_hash = runBlocking { rarime.lightRegistration(passport) }


    ///Setup Query proof parameters
    ///Replace placeholder values with your actual data
    val queryProofParams = QueryProofParams(
        eventId = "43580365239758335475",
        eventData = "0x98d622d3d4ede97469fb2152b1c9d4e4470b354db2c07afaa3846ca0d885af",
        selector = "3072",
        timestampLowerbound = "0",
        timestampUpperbound = "0",
        identityCountLowerbound = "0",
        identityCountUpperbound = "0",
        birthDateLowerbound = "0x303030303030",
        birthDateUpperbound = "0x303030303030",
        expirationDateLowerbound = "0x303030303030",
        expirationDateUpperbound = "0x303030303030",
        citizenshipMask = "0x00"
    )

    /**
     * Performs a zero-knowledge proof generation based on the provided query parameters.
     *
     * ⚠️ This is a computationally intensive cryptographic operation.
     * Expected execution time: up to ~5 seconds depending on hardware.
     * Memory usage may be significant (hundreds of MB or more).
     *
     * For best performance, execute this method in a background coroutine (`Dispatchers.Default`)
     * or dedicated worker thread.
     */
    val queryProf = runBlocking {
        rarime.generateQueryProof(
            passport = passport, queryParams = queryProofParams
        )
    }

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
