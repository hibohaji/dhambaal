from dataclasses import dataclass
from typing import List



@dataclass
class Address:
    name: str
    loaction:str

    def __repr__(self):
        return f"{self.name}, {self.loaction}"


# address_1 = Address("Hodan",'KM4 Road')
# print(address_1)

ADRESS = [
Address("Hodan",'KM4 Road'),
Address("Wadajir",'Wadajir Road'),
Address("Waberi",'Waberi Road')
]

@dataclass
class Company:
    name: str
    address:List[Address]

    def address_method(self):
        # print(self.address)
        for address in self.address:
            print(address)

somaliREN = Company("SomaliREN",address=ADRESS)
print(somaliREN.address_method())

