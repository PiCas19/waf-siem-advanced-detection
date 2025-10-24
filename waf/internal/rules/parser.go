package rules

import (
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadRulesFromFile(path string) ([]Rule, error) {
	var rules []Rule

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &rules)
	return rules, err
}

func LoadRulesFromDir(dir string) ([]Rule, error) {
	var allRules []Rule

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		path := dir + "/" + file.Name()
		rules, err := LoadRulesFromFile(path)
		if err != nil {
			continue
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}