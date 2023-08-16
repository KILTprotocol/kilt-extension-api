/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import {
  CTypeHash,
  DecryptCallback,
  DidDocument,
  DidResolveKey,
  DidResourceUri,
  DidUri,
  EncryptCallback,
  IAttestation,
  ICType,
  ICredential,
  ICredentialPresentation,
  IDelegationNode,
  PartialClaim,
} from '@kiltprotocol/types'
import * as Kilt from '@kiltprotocol/sdk-js'
import {
  blake2AsU8a,
  keyExtractPath,
  keyFromPath,
  mnemonicToMiniSecret,
  randomAsHex,
  sr25519PairFromSeed,
} from '@polkadot/util-crypto'
import {
  IEncryptedMessage,
  IError,
  IMessage,
  IQuoteAgreement,
  IQuoteAttesterSigned,
  IRequestCredential,
  MessageBody,
} from '../types'
import { fromBody } from './utils'
import { encrypt, decrypt } from './Crypto'
import { KeyError } from './Error'
import { stringToU8a, u8aToHex } from '@polkadot/util'

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
