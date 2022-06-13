import { useState, useEffect } from 'react'
import { getExtensions } from '../src/getExtension/getExtension'
import { InjectedWindowProvider } from '../src/types/types'

export default function useSporran() {
  const [extensionEnabled, setExtensionEnabled] = useState(false)
  const [extensions, setExtensions] =
    useState<Record<string, InjectedWindowProvider>>()

  useEffect(() => {
    async function doEffect() {
      const allInjected = await getExtensions()
      if (allInjected) {
        setExtensions(allInjected)
      }
      setExtensionEnabled(true)
    }
    doEffect()
  }, [])

  useEffect(() => {
    if (extensionEnabled) {
      console.log(extensions)
    }
  }, [extensionEnabled, extensions])

  return { extensions }
}
