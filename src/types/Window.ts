/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DidResourceUri, KiltAddress } from '@kiltprotocol/types'
import { HexString } from './Imported.js'

import { PubSubSessionV1, PubSubSessionV2 } from './index.js'

export type This = typeof globalThis

export interface InjectedWindowProvider<T> {
  startSession: (dAppName: string, dAppEncryptionKeyId: DidResourceUri, challenge: string) => Promise<T>
  name: string
  version: string
  specVersion: '1.0' | '3.0'
  signWithDid: (plaintext: string) => Promise<{ signature: string; didKeyUri: DidResourceUri }>
  signExtrinsicWithDid: (
    extrinsic: HexString,
    signer: KiltAddress
  ) => Promise<{ signed: HexString; didKeyUri: DidResourceUri }>
  getSignedDidCreationExtrinsic: (submitter: KiltAddress) => Promise<{ signedExtrinsic: HexString }>
}

export interface ApiWindow extends This {
  kilt: Record<string, InjectedWindowProvider<PubSubSessionV1 | PubSubSessionV2>>
}
