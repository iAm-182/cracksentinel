package mcpclient

import "os"

func environList() []string {
	return os.Environ()
}
