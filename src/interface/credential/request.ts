import * as Kilt from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'
import { decrypt, encrypt } from '../../messaging/Crypto'
import { fromBody } from '../../messaging/utils'

import { Session } from '../session/types'
import { IEncryptedMessage, IMessage, IRequestCredential, ISubmitCredential } from '../../types'
import { isIRequestCredential, isSubmitCredential } from '../../utils/TypeGuards'

interface ICredentialRequest {
  challenge: string
  message: IMessage
  encryptedMessage: IEncryptedMessage<IRequestCredential>
}

export async function requestCredential(
  sender: Kilt.DidUri,
  cTypes: Array<{
    cTypeHash: Kilt.CTypeHash
    trustedAttesters?: Kilt.DidUri[]
    requiredProperties?: string[]
  }>,
  encryptCallback: Kilt.EncryptCallback,
  session: Session,
  owner?: Kilt.DidUri
): Promise<ICredentialRequest> {
  const challenge = randomAsHex(24)
  const body: IRequestCredential = {
    content: {
      cTypes,
      challenge,
      owner,
    },
    type: 'request-credential',
  }

  const resolvedDid = await Kilt.Did.resolveKey(session.encryptionKeyUri)

  const message = fromBody(body, sender, resolvedDid.id)
  return { encryptedMessage: await encrypt(message, encryptCallback, session.encryptionKeyUri), message, challenge }
}

export async function verifyCredential(
  encryptedMessage: IEncryptedMessage<ISubmitCredential>,
  session: Session,
  request: ICredentialRequest,
  decryptCallback: Kilt.DecryptCallback
): Promise<IMessage<ISubmitCredential>> {
  const { message } = request

  const api = await Kilt.connect('')
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)

  if (!isSubmitCredential(decryptedMessage)) {
    throw new Error('Wrong message received.')
  }

  if (!isIRequestCredential(message)) {
    throw new Error('Wrong Request Message')
  }

  if (decryptedMessage.inReplyTo === message.messageId) {
    throw new Error('Wrong Reply to')
  }

  decryptedMessage.body.content.filter(async (credentialPresentation) => {
    const { challenge } = message.body.content
    const requestedCtype = message.body.content.cTypes.filter(
      (ctype) => ctype.cTypeHash === credentialPresentation.claim.cTypeHash
    )

    if (!requestedCtype) {
      throw new Error('Ctype does not match')
    }

    const ctypeDetails: Kilt.CType.ICTypeDetails = await Kilt.CType.fetchFromChain(
      `kilt:ctype:${requestedCtype[0].cTypeHash}`
    )

    const { $id, $schema, title, properties, type } = ctypeDetails
    const ctype = { $id, $schema, title, properties, type }

    Kilt.Credential.verifyPresentation(credentialPresentation, { ctype, challenge })
    credentialPresentation.claimerSignature.challenge === request.challenge

    const attestationChain = await api.query.attestation.attestations(credentialPresentation.rootHash)

    const attestation = Kilt.Attestation.fromChain(attestationChain, credentialPresentation.rootHash)

    if (attestation.revoked) {
      throw new Error('Revoked Credential')
    }

    const { trustedAttesters } = requestedCtype[0]
    const { owner: attestatonOwner } = attestation

    if (trustedAttesters) {
      if (!trustedAttesters.includes(attestatonOwner)) {
        throw new Error('attester is not accepted')
      }
    }
  })

  return decryptedMessage
}
