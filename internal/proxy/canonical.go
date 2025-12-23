package proxy

import (
	"math/big"
	"strings"
)

func canonicalizeRational(rat *big.Rat) string {
	denom := new(big.Int).Set(rat.Denom())

	two := big.NewInt(2)
	for new(big.Int).Mod(denom, two).Sign() == 0 {
		denom.Div(denom, two)
	}

	five := big.NewInt(5)
	for new(big.Int).Mod(denom, five).Sign() == 0 {
		denom.Div(denom, five)
	}

	if denom.Cmp(big.NewInt(1)) == 0 {
		return "n:" + ratToDecimalString(rat)
	}

	return "n:" + rat.Num().String() + "/" + rat.Denom().String()
}

func ratToDecimalString(rat *big.Rat) string {
	sign := ""
	if rat.Sign() < 0 {
		sign = "-"
		rat = new(big.Rat).Neg(rat)
	}

	num := new(big.Int).Set(rat.Num())
	denom := new(big.Int).Set(rat.Denom())

	intPart := new(big.Int).Div(num, denom)

	remainder := new(big.Int).Mod(num, denom)

	if remainder.Sign() == 0 {
		return sign + intPart.String()
	}

	var fracDigits []byte
	ten := big.NewInt(10)

	for remainder.Sign() != 0 {
		remainder.Mul(remainder, ten)
		digit := new(big.Int).Div(remainder, denom)
		remainder.Mod(remainder, denom)
		fracDigits = append(fracDigits, byte('0'+digit.Int64()))
	}

	return sign + intPart.String() + "." + string(fracDigits)
}

func parseJSONNumberToRat(lit string) (*big.Rat, bool) {
	if len(lit) == 0 {
		return nil, false
	}

	i := 0

	negative := false
	switch lit[i] {
	case '-':
		negative = true
		i++
		if i >= len(lit) {
			return nil, false
		}
	case '+':
		return nil, false
	}

	if lit[i] == '0' {
		i++
		if i < len(lit) && lit[i] >= '0' && lit[i] <= '9' {
			return nil, false
		}
	} else if lit[i] >= '1' && lit[i] <= '9' {
		for i < len(lit) && lit[i] >= '0' && lit[i] <= '9' {
			i++
		}
	} else {
		return nil, false
	}

	if i < len(lit) && lit[i] == '.' {
		i++
		if i >= len(lit) || lit[i] < '0' || lit[i] > '9' {
			return nil, false
		}
		for i < len(lit) && lit[i] >= '0' && lit[i] <= '9' {
			i++
		}
	}

	if i < len(lit) && (lit[i] == 'e' || lit[i] == 'E') {
		i++
		if i >= len(lit) {
			return nil, false
		}
		if lit[i] == '+' || lit[i] == '-' {
			i++
			if i >= len(lit) {
				return nil, false
			}
		}
		if lit[i] < '0' || lit[i] > '9' {
			return nil, false
		}
		for i < len(lit) && lit[i] >= '0' && lit[i] <= '9' {
			i++
		}
	}

	if i != len(lit) {
		return nil, false
	}

	rat := new(big.Rat)
	if _, ok := rat.SetString(lit); !ok {
		return nil, false
	}

	_ = negative

	return rat, true
}

func canonicalizeJSONNumber(lit string) (string, bool) {
	lit = strings.TrimLeft(lit, " \t\n\r")
	if len(lit) == 0 {
		return "", false
	}

	rat, ok := parseJSONNumberToRat(lit)
	if !ok {
		return "", false
	}

	if rat.IsInt() {
		num := rat.Num()
		if num.Sign() == 0 {
			return "n:0", true
		}
		return "n:" + num.String(), true
	}

	return canonicalizeRational(rat), true
}
