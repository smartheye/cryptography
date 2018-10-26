package com.github.smartheye.cryptography.util;

import java.math.BigDecimal;
import java.math.BigInteger;

public class AmountUtil {

	public static final BigInteger UNIT = BigInteger.valueOf(10).pow(18);
	
	public static final BigDecimal UNIT_BD = new BigDecimal(UNIT);
	/**
	 * 返回一个单位的数值
	 * @return
	 */
	public static final BigInteger unit(){
		return BigInteger.valueOf(10).pow(18);
	}
	
	public static final BigInteger toUnit(BigDecimal amount) {
		//System.out.println(UNIT);
		BigDecimal amountUnit = amount.multiply(UNIT_BD);
		//System.out.println(amountUnit.toPlainString());
		// 在这里不允许有小数，如果有小数的话应抛出ArithmeticException
		return amountUnit.toBigIntegerExact();
	}
}
