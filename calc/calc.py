#!/usr/bin/env python3
"""
Simple calc using object oriented programming 

to run:

python3 calc.py
"""

import math
from typing import Union

from abc import ABC, abstractmethod

# global adv_flag  # global variable to control advanced options


def main():
    calc = calc_type()
    print("To exit, CTRL + D/C")
    try:
        calc.run()
    except (KeyboardInterrupt, EOFError) as e:
        answer = input("Are you sure you want to exit? [Y]: ")
        if answer.lower() == 'y':
            raise KeyboardInterrupt from e


def calc_type():
    """
    Returns:
        str: 'basic' or 'advanced'
    """
    while True:
        calc_type = input(
            "Basic, Advanced, or bitwise Calculator? [B/A/bit]: ")
        if calc_type.lower() == 'b':
            return BasicCalc()
        elif calc_type.lower() == 'a':
            return AdvancedCalc()
        elif calc_type.lower() == 'bit':
            return BitCalc()


class Calc(ABC):  # may want to add __init__ if there's special values for handling

    @abstractmethod
    def __init__(self):
        self.commands = {}

    def calc_menu(self) -> None:
        """
        calc_menu doc string

        shows menu of calculator options
        """
        print("CALCULATOR OPTIONS\n")
        for key, value in self.commands.items():
            print(f"\t{key}. {value.__name__}", sep=". ")

    def get_numbers(self) -> Union[int, float]:
        """get_numbers 

        converts string to integer or a float
        :return: data back to the calling function
        :rtype: Union[int, float]
        """
        self.value1 = input("Enter first value: ").strip()
        try:
            if '.' in self.value1:
                num1 = float(self.value1)
            else:
                num1 = int(self.value1)
        except (ValueError, TypeError):
            print("error! invalid data \n Try again")
        return num1

    def run(self) -> None:
        """run prorgram

        gets calc type from user and runs the appropriate calc
        """
        while (1):
            self.calc_menu()
            cmd = input("How can I help you?\n")
            if cmd in self.commands:
                results = self.commands[cmd]()
                print(results)
            elif cmd not in self.commands:
                print("outside menu\n")


class BasicCalc(Calc):

    def __init__(self) -> None:
        super().__init__()
        self.commands["1"] = self.add
        self.commands["2"] = self.subtract
        self.commands["3"] = self.multiply
        self.commands["4"] = self.divide

    def add(cls) -> Union[int, float]:
        """add function 

        adds two numbers together

        :return: one numeric value
        :rtype: Union[int, float]
        """
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        return num1 + num2

    def subtract(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        return num1 - num2

    def divide(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        if num1 == 0:
            raise ZeroDivisionError
        return num1 / num2

    def multiply(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        return num1 * num2


class AdvancedCalc(BasicCalc):

    def __init__(self):
        super().__init__()
        self.commands["5"] = self.mod
        self.commands["6"] = self.power
        self.commands["7"] = self.squareroot
        self.commands["8"] = self.factorial

    def mod(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        return num1 % num2

    def power(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        return math.pow(num1, num2)

    def squareroot(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        return math.sqrt(num1)

    def factorial(cls) -> Union[int, float]:
        num1 = cls.get_numbers()
        return math.factorial(num1)


class BitCalc(Calc):

    def __init__(self):
        super().__init__()
        self.commands["1"] = self.bitwise_and
        self.commands["2"] = self.bitwise_or
        self.commands["3"] = self.bitwise_xor
        self.commands["4"] = self.bitwise_shift_right
        self.commands["5"] = self.bitwise_shift_left

    def bitwise_and(cls) -> bin:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        bin_num = num1 & num2
        return bin(bin_num)

    def bitwise_or(cls) -> bin:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        bin_num = num1 | num2
        return bin(bin_num)

    def bitwise_xor(cls) -> bin:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        bin_num = (num1 ^ num2)
        return bin(bin_num)

    def bitwise_shift_right(cls) -> bin:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        bin_num = num1 >> num2
        return bin(bin_num)

    def bitwise_shift_left(cls) -> bin:
        num1 = cls.get_numbers()
        num2 = cls.get_numbers()
        bin_num = num1 << num2
        return bin(bin_num)


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("Have a nice day")
    except (SystemExit, GeneratorExit, Exception) as err:
        print("Error: ", err)
        print("Error.__cause__", err.__cause__)
        print("Error.__class__", err.__class__.__name__)
        print("Error.with_traceback", err.with_traceback)
        # pass exists only for when debug off, so last line ends with a \n
        pass
