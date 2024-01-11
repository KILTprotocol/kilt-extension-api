/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

export class MessageError extends Error {}
export class HashMalformedError extends MessageError {}
export class SignatureMalformedError extends MessageError {}
export class UnknownMessageBodyTypeError extends MessageError {}
export class DecodingMessageError extends MessageError {}
export class CTypeUnknownPropertiesError extends MessageError {}
export class InvalidDidFormatError extends MessageError {}
export class KeyError extends MessageError {}
export class DidError extends MessageError {}
export class IdentityMismatchError extends MessageError {}
