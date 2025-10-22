package main

type User struct {
	ID       int
	Email    string
	Password string
}

type StockQuote struct {
	Symbol  string  `json:"symbol"`
	Open    float64 `json:"o"`
	High    float64 `json:"h"`
	Low     float64 `json:"l"`
	Current float64 `json:"c"`
}
