/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

export declare class MessageError extends Error {}

export declare class HashMalformedError extends MessageError {
  constructor(hash?: string, type?: string)
}

export declare class SignatureMalformedError extends MessageError {}
export declare class UnknownMessageBodyTypeError extends MessageError {}
export declare class DecodingMessageError extends MessageError {}
export declare class IdentityMismatchError extends MessageError {
  constructor(context?: string, type?: string)
}