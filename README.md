# argon2-cloudflare

This repository contains a Cloudflare worker for hashing and verifying passwords with argon2.

It exposes both fetch and RPC bindings, which can both be enabled or disabled using features.

## Install

Ensure that you have a Rust toolchain (if not install one with `rustup-init`) and [Bun](https://bun.sh) installed.

```sh
bun install
```

## Features

The worker uses features defined in [Cargo.toml](./Cargo.toml) to conditionally enable and disable the RPC handlers and the HTTP handlers.

Which will be enabled is controlled via the build command setting in the [wrangler config](./wrangler.toml).

The current [wrangler config](./wrangler.toml) only enables the RPC handlers and disables the <workers.dev> subdomain.

```toml
# Disables the workers.dev subdomain
workers_dev = false

[build]
# Enable both the RPC and HTTP features
# command = "cargo install -q worker-build && worker-build --release"

# Enable only the RPC feature
command = "cargo install -q worker-build && worker-build --release --no-default-features --features rpc"

# Enable only the HTTP feature
# command = "cargo install -q worker-build && worker-build --release --no-default-features --features http"
```

## Development

```sh
bun dev
```

The worker will build and launch with the features that are enabled in the build command.

When the local development server is running, the worker is accessible as `argon2` to other workers.

## Deploy to Cloudflare

```sh
bun run deploy
```

## TypeScript bindings

For convenience, the [workers.ts](./worker.ts) module contains type definitions and helpers for interacting with the service both via RPC stubs and fetch.

## API

The worker exposes both a `hash` and a `verify` RPC handler function.

These functions are also exposed as HTTP POST endpoints at `/hash` and `/verify` respectively.

```ts
export interface Argon2Options {
  timeCost: number;
  memoryCost: number;
  parallelism: number;
}

export interface HashRequest {
  password: string;
  options?: Partial<Argon2Options> | undefined;
}

export interface HashResponse {
  hash: string;
}

export interface VerifyRequest {
  password: string;
  hash: string;
}

export interface VerifyResponse {
  matches: boolean;
}

export interface Argon2Worker extends WorkerEntrypoint {
  hash(request: HashRequest): Promise<HashResponse>;
  verify(request: VerifyRequest): Promise<VerifyResponse>;
}
```

An example implementation for using the service via both RPC and HTTP bindings is provided in the [worker.ts](./worker.ts) module.

### RPC

The example code here assumes that the service binding is bound to `argon2`.

#### Hash

```ts
// Hashing a password with default options
const { hash } = await env.argon2.hash({
  password: "password"
})

// Hashing a password with custom options
const { hash } = await env.argon2.hash({
  password: "password",
  options: {
    timeCost: 2,
    memoryCost: 19456,
    parallelism: 1
  }
})
```

#### Verify

```ts
// Verifying a password
const { matches } = await env.argon2.verify({
  password: "password",
  hash: "<SOME ARGON2 HASH>"
})
```

### HTTP

#### Hash (`POST /hash`)

Endpoint: `POST /hash`

##### Request

Using the default options:

```json
{
  "password": "password",
}
```

Using custom options:

```json
{
  "password": "password",
  "options": {
    "timeCost": 2,
    "memoryCost": 19456,
    "parallelism": 1
  },
}
```

##### Response

```json
{
  "hash": "<SOME ARGON2 HASH>"
}
```

#### Verify (`POST /verify`)

Endpoint: `POST /verify`

##### Request

```json
{
  "password": "password",
  "hash": "<SOME ARGON2 HASH>",
}
```

##### Response

```json
{
  "matches": true
}
```

```json
{
  "matches": false
}
```

## Acknowledgements

This repository is a fork of and largely based on [glotlabs/argon2-cloudflare](https://github.com/glotlabs/argon2-cloudflare).

## License

[MIT](./LICENSE)
