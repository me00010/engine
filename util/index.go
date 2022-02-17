package util

import (
	"constraints"
	"os"
	"path/filepath"
	"runtime"
)

func Clone[T any](x T) *T {
	return &x
}

func CurrentDir(path ...string) string {
	if _, currentFilePath, _, _ := runtime.Caller(1); len(path) == 0 {
		return filepath.Dir(currentFilePath)
	} else {
		return filepath.Join(filepath.Dir(currentFilePath), filepath.Join(path...))
	}
}

// 检查文件或目录是否存在
// 如果由 filename 指定的文件或目录存在则返回 true，否则返回 false
func Exist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func ConvertNum[F constraints.Integer, T constraints.Integer](from F, to T) T {
	return T(from)
}

// Bit1 检查字节中的某一位是否为1 |0|1|2|3|4|5|6|7|
func Bit1(b byte, index int) bool {
	return b&(1<<(7-index)) != 0
}