/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { DidUri as Did } from '@kiltprotocol/types'
import type { constants } from '@kiltprotocol/vc-export'

import { DOMAIN_LINKAGE_CREDENTIAL_TYPE } from '../wellKnownDidConfiguration/index.js'
import type { SelfSignedProof } from './LegacyProofs.js'

export type CredentialSubject = {
  id: Did
  origin: string
}

type Contexts = [
  typeof constants.DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
  'https://identity.foundation/.well-known/did-configuration/v1',
  ...string[],
]

export type DataIntegrityProof = {
  type: 'DataIntegrity'
  verificationMethod: string
  cryptosuite: string
  proofPurpose: string
  proofValue: string
  created?: string
  expires?: string
  domain?: string
  challenge?: string
  previousProof?: string
}

export type DomainLinkageProof = SelfSignedProof | DataIntegrityProof

export type DidConfigResource = {
  '@context': string
  linked_dids: DomainLinkageCredential[]
}

export type DomainLinkageCredential = {
  '@context': Contexts
  type: (typeof constants.DEFAULT_VERIFIABLECREDENTIAL_TYPE | typeof DOMAIN_LINKAGE_CREDENTIAL_TYPE | string)[]
  credentialSubject: CredentialSubject
  issuer: string
  issuanceDate: string
  expirationDate: string
  proof: DomainLinkageProof
}
