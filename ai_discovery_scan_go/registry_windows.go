//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// checkWindowsRegistrySoftware checks Windows registry for software entries.
func checkWindowsRegistrySoftware(software string, regPaths []registryPath) []DetectionResult {
	var results []DetectionResult
	for _, rp := range regPaths {
		key, err := registry.OpenKey(rp.Root, rp.Path, registry.READ)
		if err != nil {
			continue
		}
		defer key.Close()

		// If this is an Uninstall key, enumerate subkeys
		if strings.Contains(rp.Path, "Uninstall") {
			subkeys, err := key.ReadSubKeyNames(-1)
			if err != nil {
				continue
			}
			for _, sk := range subkeys {
				if strings.Contains(strings.ToLower(sk), strings.ToLower(software)) {
					subKey, err := registry.OpenKey(key, sk, registry.READ)
					if err != nil {
						continue
					}
					displayName, _, err := subKey.GetStringValue("DisplayName")
					subKey.Close()
					if err == nil {
						results = append(results, DetectionResult{
							Software:      software,
							DetectionType: "registry_key",
							Value:         fmt.Sprintf("Uninstall entry: %s", displayName),
							Confidence:    "high",
						})
					}
				}
			}
			continue
		}

		// Enumerate values
		values, err := key.ReadValueNames(-1)
		if err != nil {
			continue
		}
		for _, valName := range values {
			valStr, _, err := key.GetStringValue(valName)
			if err != nil {
				continue
			}
			if strings.Contains(strings.ToLower(valName), strings.ToLower(software)) ||
				strings.Contains(strings.ToLower(valStr), strings.ToLower(software)) {
				results = append(results, DetectionResult{
					Software:      software,
					DetectionType: "registry_key",
					Value:         fmt.Sprintf("%s\\%s=%s", rp.Path, valName, valStr),
					Confidence:    "high",
				})
			}
		}
	}
	return results
}

type registryPath struct {
	Root registry.Key
	Path string
}

func checkWindowsRegistryOllama() []DetectionResult {
	return checkWindowsRegistrySoftware("Ollama", []registryPath{
		{registry.CURRENT_USER, `Software\Ollama`},
		{registry.LOCAL_MACHINE, `Software\Ollama`},
		{registry.CURRENT_USER, `Environment`},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`},
	})
}

func checkWindowsRegistryLMStudio() []DetectionResult {
	return checkWindowsRegistrySoftware("LM Studio", []registryPath{
		{registry.CURRENT_USER, `Software\LMStudio`},
		{registry.LOCAL_MACHINE, `Software\LMStudio`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	})
}

func checkWindowsRegistryGPT4All() []DetectionResult {
	return checkWindowsRegistrySoftware("GPT4All", []registryPath{
		{registry.CURRENT_USER, `Software\GPT4All`},
		{registry.LOCAL_MACHINE, `Software\GPT4All`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
	})
}

func checkWindowsRegistryVLLM() []DetectionResult {
	return checkWindowsRegistrySoftware("vLLM", []registryPath{
		{registry.CURRENT_USER, `Software\vLLM`},
		{registry.LOCAL_MACHINE, `Software\vLLM`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
	})
}

func checkWindowsRegistryFromRule(software string) []DetectionResult {
	return checkWindowsRegistrySoftware(software, []registryPath{
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	})
}
