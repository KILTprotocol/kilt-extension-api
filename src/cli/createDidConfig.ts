#!/usr/bin/env node

/**
 * Copyright (c) 2018-2023, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Credential, Did, connect, disconnect } from '@kiltprotocol/sdk-js'
import { DidResourceUri, DidUri, ICredentialPresentation, SignCallback } from '@kiltprotocol/types'

import { Keyring } from '@polkadot/keyring'
import { u8aEq } from '@polkadot/util'

import { readFile, writeFile } from 'fs/promises'
import yargs from 'yargs/yargs'

import { didConfigResourceFromCredential, createCredential } from '../wellKnownDidConfiguration/index.js'
import type { DidConfigResource } from '../types/index.js'

type KeyType = 'sr25519' | 'ed25519' | 'ecdsa'

const commonOpts = { outFile: { alias: 'f', type: 'string' } } as const
const createCredentialOpts = {
  origin: { alias: 'o', type: 'string', demandOption: true },
  did: {
    alias: 'd',
    type: 'string',
    demandOption: true,
    description:
      'DID of the issuer (and subject) of the Domain Linkage Credential. If omitted, this is attempted to be inferred from the assertionMethod.',
  },
  seed: {
    type: 'string',
    alias: 's',
    description: 'Mnemonic or seed for the assertionMethod key to be used for issuing a new credential.',
    demandOption: true,
  },
  keyType: { alias: 't', choices: ['sr25519', 'ed25519', 'ecdsa'] as const, default: 'ed25519' },
  wsAddress: { alias: 'w', type: 'string', demandOption: true, default: 'wss://spiritnet.kilt.io' },
} as const

async function issueCredential(did: DidUri, origin: string, seed: string, keyType: KeyType, nodeAddress: string) {
  await connect(nodeAddress)
  const didDocument = await Did.resolve(did)
  const assertionMethod = didDocument?.document?.assertionMethod?.[0]
  if (!assertionMethod) {
    throw new Error(
      `Could not resolve assertionMethod of ${did}. Make sure the DID is registered to this chain and has an assertionMethod key.`
    )
  }
  const keypair = new Keyring({ type: keyType }).addFromUri(seed)
  if (assertionMethod.type !== keypair.type || !u8aEq(assertionMethod.publicKey, keypair.publicKey)) {
    throw new Error('public key and/or key type of the DIDs assertionMethod does not match the supplied signing key')
  }
  const keyUri: DidResourceUri = `${didDocument!.document!.uri}${assertionMethod.id}`
  const signCallback: SignCallback = async ({ data }) => ({ signature: keypair.sign(data), keyUri, keyType })
  const credential = await createCredential(signCallback, origin, did)
  return credential
}

async function write(toWrite: unknown, outPath?: string) {
  const stringified = JSON.stringify(toWrite, null, 2)
  if (outPath) {
    await writeFile(outPath, stringified)
  } else {
    console.log(stringified)
  }
}

async function run() {
  await yargs(process.argv.slice(2))
    .command(
      'fromCredential <pathToCredential>',
      'create a Did Configuration Resource from an existing Kilt Credential Presentation',
      (ygs) =>
        ygs.options(commonOpts).positional('pathToCredential', {
          describe: 'Path to a json file containing the credential presentation',
          type: 'string',
          demandOption: true,
        }),
      async ({ pathToCredential, outFile }) => {
        let credential: ICredentialPresentation
        try {
          credential = JSON.parse(await readFile(pathToCredential, { encoding: 'utf-8' }))
        } catch (cause) {
          throw new Error(`Cannot parse file ${pathToCredential}`, { cause })
        }
        if (!Credential.isPresentation(credential)) {
          throw new Error(`Malformed Credential Presentation loaded from ${pathToCredential}`)
        }
        let didResource: DidConfigResource
        try {
          didResource = await didConfigResourceFromCredential(credential)
        } catch (cause) {
          throw new Error('Credential Presentation is not suitable for use in a Did Configuration Resource', {
            cause,
          })
        }
        await write(didResource, outFile)
      }
    )
    .command(
      'credentialOnly',
      'issue a new Kilt Credential Presentation for use in a Did Configuration Resource',
      { ...createCredentialOpts, ...commonOpts },
      async ({ origin, seed, keyType, wsAddress, outFile, did }) => {
        const credential = await issueCredential(did as DidUri, origin, seed, keyType, wsAddress)
        await write(credential, outFile)
      }
    )
    .command(
      '$0',
      'create a Did Configuration Resource from a freshly issued Kilt Credential',
      { ...createCredentialOpts, ...commonOpts },
      async ({ origin, seed, keyType, wsAddress, outFile, did }) => {
        const credential = await issueCredential(did as DidUri, origin, seed, keyType, wsAddress)
        const didResource = await didConfigResourceFromCredential(credential)
        await write(didResource, outFile)
      }
    )
    .parseAsync()
}

run()
  .catch(async (e) => {
    process.exitCode = 1
    console.error(e)
  })
  .finally(disconnect)
