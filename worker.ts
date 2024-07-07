/**
 * @module worker
 * 
 * This module contains TypeScript types for interacting with the argon2 worker.
 * 
 * It contains type definitions, zod schemas, and service classes for interacting with the worker via RPC and HTTP.
 */
// This file contains the TypeScript types for the worker's entrypoint.

import type { Fetcher } from "@cloudflare/workers-types";
import type { WorkerEntrypoint } from "cloudflare:workers";
import { z } from "zod";

// Types

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

export interface Argon2Service {
  hash(password: string, options?: Argon2Options | undefined): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
}

// zod schemas

export const hashRequestSchema = z.object({
  password: z.string(),
  options: z.object({
    timeCost: z.number(),
    memoryCost: z.number(),
    parallelism: z.number()
  }).optional()
});

export const hashResponseSchema = z.object({
  hash: z.string()
});

export const verifyRequestSchema = z.object({
  password: z.string(),
  hash: z.string()
});


export const verifyResponseSchema = z.object({
  matches: z.boolean()
});

// RPC Stub service

export class Argon2StubService implements Argon2Service {
  readonly #stub: Fetcher<Argon2Worker>;

  constructor(stub: Fetcher<Argon2Worker>) {
    this.#stub = stub;
  }

  async hash(password: string, options?: Argon2Options | undefined): Promise<string> {
    const request = hashRequestSchema.parse({ password, options });
    const response = await (this.#stub.hash(request) as Promise<HashResponse>);
    const { hash } = hashResponseSchema.parse(response);
    return hash;
  }

  async verify(password: string, hash: string): Promise<boolean> {
    const request = verifyRequestSchema.parse({ password, hash });
    const response = await (this.#stub.verify(request) as Promise<VerifyResponse>);
    const { matches } = verifyResponseSchema.parse(response);
    return matches;
  }
}

// Fetch service

export class Argon2FetchService implements Argon2Service {
  readonly #hashUrl: string;
  readonly #verifyUrl: string;

  constructor(baseUrl: string) {
    this.#hashUrl = `${baseUrl}/hash`;
    this.#verifyUrl = `${baseUrl}/verify`;
  }

  async hash(password: string, options?: Argon2Options | undefined): Promise<string> {
    const request = hashRequestSchema.parse({ password, options });
    const response = await fetch(this.#hashUrl, {
      method: "POST",
      body: JSON.stringify(request),
      headers: {
        "Content-Type": "application/json"
      }
    });
    const body = await response.json();
    const { hash } = hashResponseSchema.parse(body);
    return hash;
  }

  async verify(password: string, hash: string): Promise<boolean> {
    const request = verifyRequestSchema.parse({ password, hash });
    const response = await fetch(this.#verifyUrl, {
      method: "POST",
      body: JSON.stringify(request),
      headers: {
        "Content-Type": "application/json"
      }
    });
    const body = await response.json();
    const { matches } = verifyResponseSchema.parse(body);
    return matches;
  }
}
