import {
  KeyringPair,
  DidUri,
  init,
  DidDocument,
} from '@kiltprotocol/sdk-js'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import { VerifiableDomainLinkagePresentation } from '../types/types'
import { Keyring } from '@kiltprotocol/utils'

import { createCredential } from './wellKnownDidConfiguration'
import { assertionSigner, generateDid, keypairs } from '../tests/utils'

describe('Well Known Did Configuration integration test', () => {
  let mnemonic: string
  let account: KeyringPair
  const origin = 'http://localhost:3000'
  let didDocument: DidDocument
  let didUri: DidUri
  let keypair: any
  // let domainLinkageCredential: VerifiableDomainLinkagePresentation
  // let credential: ICredential
  // let expirationDate: string

  beforeAll(async () => {
    // mnemonic = mnemonicGenerate()
    await init({ address: 'wss://peregrine.kilt.io/' })
    mnemonic =
      'gesture ocean hurry disagree control twin script evidence under pottery route galaxy'
    account = new Keyring({ type: 'sr25519' }).addFromMnemonic(mnemonic)
    keypair = await keypairs(account, mnemonic)
    didDocument = await generateDid(account, mnemonic, keypair.assertion.sign)
    didUri = didDocument.uri
  })

  it('generate a well known did configuration credential', async () => {
    expect(
      await createCredential(
        await assertionSigner({ assertion: keypair.assertion, didDocument }),
        origin,
        didUri
      )
    ).toBeCalled()
  })
})
