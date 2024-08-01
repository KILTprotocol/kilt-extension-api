/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { SDKErrors } from '@kiltprotocol/sdk-js'

export class UnknownMessageBodyTypeError extends SDKErrors.SDKError {}
export class DecodingMessageError extends SDKErrors.SDKError {}
export class CTypeUnknownPropertiesError extends SDKErrors.SDKError {}
export class KeyError extends SDKErrors.SDKError {}
export class IdentityMismatchError extends SDKErrors.SDKError {
  constructor(context?: string, type?: string) {
    super(`Identity mismatch${context ? ` in context: ${context}` : ''}${type ? ` of type ${type}` : ''}`)
    this.name = 'IdentityMismatchError'
  }
}