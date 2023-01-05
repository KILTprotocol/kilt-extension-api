/**
 * Detection and global state for sporran wallet
 *
 * Detect wallet in a component's mounted() and updated() hooks with: this.$wallet.checkForExtension()
 *
 * Use the wallet with: this.$wallet.getInstance()
 */

import Vue from 'vue'
// import { DidPublicKey, IEncryptedMessage } from '@kiltprotocol/sdk-js'
import { getExtensions } from '../src/getExtension'

function walletSetup() {
  let instance: null = null

  async function checkForExtension() {
    const allInjected = await getExtensions()

    if (Array.isArray(allInjected) && allInjected.length) {
      allInjected.forEach((extension) => {
        if (extension.name === 'sporran') {
          instance = extension
        }
      })
    }
  }

  function getInstance() {
    return instance
  }

  return {
    checkForExtension,
    getInstance,
  }
}

export default function (app) {
  Vue.prototype.$wallet = walletSetup()
}
