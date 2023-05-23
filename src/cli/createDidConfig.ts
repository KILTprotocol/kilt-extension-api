#!/usr/bin/env node

import { Credential, Did, connect, disconnect } from '@kiltprotocol/sdk-js'
import { DidResourceUri, ICredentialPresentation, SignCallback } from '@kiltprotocol/types'
import { readFile, writeFile } from 'fs/promises'
import yargs from 'yargs/yargs'
import { Keyring } from '@polkadot/keyring'

import { makeDidConfigResourceFromCredential, createCredential } from '../wellKnownDidConfiguration'
import { DidConfigResource } from '../types'

type KeyType = 'sr25519' | 'ed25519' | 'ecdsa'

async function issueCredential(
  keyUri: DidResourceUri,
  origin: string,
  seed: string,
  keyType: KeyType,
  nodeAddress: string
) {
  await connect(nodeAddress)
  const { did } = Did.parse(keyUri)
  const keypair = new Keyring({ type: keyType }).addFromUri(seed)
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
  const args = await yargs(process.argv.slice(2))
    .command(
      'fromCredential <pathToCredential>',
      'create a Did Configuration Resource from an existing Kilt Credential Presentation',
      (ygs) =>
        ygs
          .options({
            outFile: { alias: 'f', type: 'string' },
          })
          .positional('pathToCredential', {
            describe: 'Path to a json file containing the credential presentation',
            type: 'string',
            demandOption: true,
          }),
      async ({ pathToCredential, outFile }) => {
        let credential: ICredentialPresentation
        try {
          credential = JSON.parse(await readFile(pathToCredential, { encoding: 'utf-8' }))
          if (!Credential.isPresentation(credential)) {
            throw new Error()
          }
        } catch (error) {
          throw new Error('fromCredential does not resolve to a valid Kilt Credential Presentation')
        }
        let didResource: DidConfigResource
        try {
          didResource = await makeDidConfigResourceFromCredential(credential)
        } catch (e) {
          throw new Error('Credential Presentation is not suitable for use in a Did Configuration Resource')
        }
        await write(didResource, outFile)
      }
    )
    .command(
      'makeCredential',
      'issue a new Kilt Credential Presentation for use in a Did Configuration Resource',
      {
        origin: { alias: 'o', type: 'string', demandOption: true },
        assertionMethod: { alias: 'k', type: 'string', demandOption: true },
        seed: {
          type: 'string',
          alias: 's',
          description: 'Mnemonic or seed for the assertionMethod key to be used for issuing a new credential.',
          demandOption: true,
        },
        keyType: { alias: 't', choices: ['sr25519', 'ed25519', 'ecdsa'], default: 'sr25519' },
        outFile: { alias: 'f', type: 'string' },
        wsAddress: { alias: 'w', type: 'string', demandOption: true, default: 'wss://spiritnet.kilt.io' },
      },
      async ({ assertionMethod, origin, seed, keyType, wsAddress, outFile }) => {
        const credential = await issueCredential(
          assertionMethod as DidResourceUri,
          origin,
          seed,
          keyType as KeyType,
          wsAddress
        )
        await write(credential, outFile)
      }
    )
    .command(
      '$0',
      'create a Did Configuration Resource from a freshly issued Kilt Credential',
      {
        origin: { alias: 'o', type: 'string', demandOption: true },
        assertionMethod: { alias: 'k', type: 'string', demandOption: true },
        seed: {
          type: 'string',
          alias: 's',
          description: 'Mnemonic or seed for the assertionMethod key to be used for issuing a new credential.',
          demandOption: true,
        },
        keyType: { alias: 't', choices: ['sr25519', 'ed25519', 'ecdsa'], default: 'sr25519' },
        outFile: { alias: 'f', type: 'string' },
        wsAddress: { alias: 'w', type: 'string', demandOption: true, default: 'wss://spiritnet.kilt.io' },
      },
      async ({ assertionMethod, origin, seed, keyType, wsAddress, outFile }) => {
        const credential = await issueCredential(
          assertionMethod as DidResourceUri,
          origin,
          seed,
          keyType as KeyType,
          wsAddress
        )
        const didResource = await makeDidConfigResourceFromCredential(credential)
        await write(didResource, outFile)
      }
    )
    .parseAsync()
}

run()
  .catch((e) => console.error(e))
  .finally(disconnect)
