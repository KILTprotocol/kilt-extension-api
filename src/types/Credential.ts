/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { DataIntegrity, W3C_CREDENTIAL_CONTEXT_URL, W3C_CREDENTIAL_TYPE } from '@kiltprotocol/credentials'
import type { Did } from '@kiltprotocol/types'

import { DOMAIN_LINKAGE_CREDENTIAL_TYPE } from '../wellKnownDidConfiguration/index.js'
import type { SelfSignedProof } from './LegacyProofs.js'

export interface CredentialSubject {
  id: Did
  origin: string
}

type Contexts = [
  typeof W3C_CREDENTIAL_CONTEXT_URL,
  'https://identity.foundation/.well-known/did-configuration/v1',
  ...string[],
]

export type DomainLinkageProof = SelfSignedProof | DataIntegrity.DataIntegrityProof

export interface DidConfigResource {
  '@context': string
  linked_dids: DomainLinkageCredential[]
}

export interface DomainLinkageCredential {
  '@context': Contexts
  type: (typeof W3C_CREDENTIAL_TYPE | typeof DOMAIN_LINKAGE_CREDENTIAL_TYPE | string)[]
  credentialSubject: CredentialSubject
  issuer: string
  issuanceDate: string
  expirationDate: string
  proof: DomainLinkageProof
}
