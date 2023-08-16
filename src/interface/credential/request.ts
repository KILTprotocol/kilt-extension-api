import * as Kilt from '@kiltprotocol/sdk-js'
import { randomAsHex } from '@polkadot/util-crypto'
import { encrypt } from '../../messaging/Crypto'
import { fromBody } from '../../messaging/utils'

import { Session } from '../session/types'
import { IEncryptedMessage, IRequestCredential } from '../../types'

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
): Promise<IEncryptedMessage<IRequestCredential>> {
  const challenge = randomAsHex(24)
  const body: IRequestCredential = {
    content: {
      cTypes,
      challenge,
      owner,
    },
    type: 'request-credential',
  }

  // TODO: is this possible?
  const resolvedDid = await Kilt.Did.resolveKey(session.encryptionKeyUri)

  const message = fromBody(body, sender, resolvedDid.id)
  return encrypt(message, encryptCallback, session.encryptionKeyUri)
}

export async function verifyCredential() {
  return 'TODO'
}
