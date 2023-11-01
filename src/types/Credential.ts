import { DidUri } from '@kiltprotocol/types'
import { VerifiableCredential, constants } from '@kiltprotocol/vc-export'

import { IMessageWorkflow } from './index.js'
import { DomainLinkageProof } from './Window.js'

export type ICredentialRequest = IMessageWorkflow & {
  challenge: string
}

export interface CredentialSubject {
  id: DidUri
  origin: string
}

type Contexts = [
  typeof constants.DEFAULT_VERIFIABLECREDENTIAL_CONTEXT,
  'https://identity.foundation/.well-known/did-configuration/v1',
]

export interface DomainLinkageCredential
  extends Omit<VerifiableCredential, '@context' | 'legitimationIds' | 'credentialSubject' | 'proof' | 'id'> {
  '@context': Contexts
  credentialSubject: CredentialSubject
  proof: DomainLinkageProof
}
