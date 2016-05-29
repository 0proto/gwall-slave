package modules

type ModuleError struct {
	Error   error
	Message string
	Code    int
}
