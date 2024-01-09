/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Did } from '@kiltprotocol/types'
import { Types, W3C_CREDENTIAL_CONTEXT_URL } from '@kiltprotocol/credentials'

import { CredentialDigestProof, SelfSignedProof } from './LegacyProofs.js'

export interface CredentialSubject {
  id: Did
  origin: string
}

type Contexts = [typeof W3C_CREDENTIAL_CONTEXT_URL, 'https://identity.foundation/.well-known/did-configuration/v1']

export type DomainLinkageProof = {
  type: Array<SelfSignedProof['type'] | CredentialDigestProof['type']>
  rootHash: string
} & Pick<SelfSignedProof, 'signature' | 'verificationMethod' | 'proofPurpose' | 'created'> &
  Pick<CredentialDigestProof, 'claimHashes' | 'nonces'>

export interface DidConfigResource {
  '@context': string
  linked_dids: [DomainLinkageCredential]
}

export interface DomainLinkageCredential
  extends Omit<Types.VerifiableCredential, '@context' | 'credentialSubject' | 'proof' | 'id'> {
  '@context': Contexts
  credentialSubject: CredentialSubject
  proof: DomainLinkageProof
}
