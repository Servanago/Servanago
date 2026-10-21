package phpbuild

import "strconv"

func labelOf(version string, n int) string { return version + "-" + strconv.Itoa(n) }
