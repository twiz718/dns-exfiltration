package internal

type DataChunk struct {
	Start int
	End   int
	Data  []byte
}

type FileFromDNS struct {
	TotalChunks int
	DataChunks  map[int]DataChunk
}
