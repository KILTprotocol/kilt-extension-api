/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import {
  CTypeHash,
  DidUri,
  IAttestation,
  ICType,
  ICredential,
  ICredentialPresentation,
  IDelegationNode,
  PartialClaim,
} from '@kiltprotocol/types'
import { IQuoteAgreement, IQuoteAttesterSigned, MessageBody } from '../types'

export function createErrorMesssageBody(name = 'Error', message: string | undefined): MessageBody {
  return {
    content: {
      name,
      message,
    },
    type: 'error',
  }
}

export function createRejectMesssageBody(name = 'Reject', message: string | undefined): MessageBody {
  return {
    content: {
      name,
      message,
    },
    type: 'reject',
  }
}

export function createSubmitTermsMesssageBody(
  claim: PartialClaim,
  legitimations: ICredential[],
  delegationId?: IDelegationNode['id'],
  quote?: IQuoteAttesterSigned,
  cTypes?: ICType[]
): MessageBody {
  return {
    content: {
      claim,
      legitimations,
      cTypes,
      delegationId,
      quote,
    },
    type: 'submit-terms',
  }
}

export function createRequestAttestationMessageBody(credential: ICredential, quote?: IQuoteAgreement): MessageBody {
  return {
    content: {
      credential,
      quote,
    },
    type: 'request-attestation',
  }
}

export function createRequestPaymentMessageBody(claimHash: string): MessageBody {
  return {
    content: {
      claimHash,
    },
    type: 'request-payment',
  }
}

export function createSubmitAttestationMessageBody(attestation: IAttestation): MessageBody {
  return {
    content: {
      attestation,
    },
    type: 'submit-attestation',
  }
}

export function createRejectAttestationMessageBody(content: ICredential['rootHash']): MessageBody {
  return {
    content,
    type: 'reject-attestation',
  }
}

export function createSubmitCredentialMessageBody(content: ICredentialPresentation[]): MessageBody {
  return {
    content,
    type: 'submit-credential',
  }
}

export function createRequestCredentialMesageBody(
  cTypes: Array<{
    cTypeHash: CTypeHash
    trustedAttesters?: DidUri[]
    requiredProperties?: string[]
  }>,
  targetDid?: DidUri,
  challenge?: string
): MessageBody {
  return {
    content: {
      cTypes,
      challenge,
      targetDid,
    },
    type: 'request-credential',
  }
}

export function createConfirmPaymentMesageBody(blockHash: string, claimHash: string, txHash: string): MessageBody {
  return {
    content: {
      blockHash,
      claimHash,
      txHash,
    },
    type: 'confirm-payment',
  }
}
