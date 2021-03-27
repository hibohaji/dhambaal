# Attributes : are normal variables defined inside a class
# Method: a function in a class
# Property and attributes are same sometimes
from datetime import datetime

class Foo:
    pass
class Employee:
    raise_up = 1.05
  
    def __init__(self,first_name,last_name,company,pay):
        self.first_name = first_name
        self.last_name = last_name
        self.company = company
        self.pay = pay

    def __repr__(self):
        return f'{self.first_name} {self.last_name} {self.company} {self.pay}'
    
    # def email(self):
    #     return f'{self.first_name}.{self.last_name}@{self.company}.com'
    @property   
    def email(self):
        return f'{self.first_name}.{self.last_name}@{self.company}.com'
    
    def yearly_raise(self):
        self.pay = int(self.pay*self.raise_up)
    
    @staticmethod
    def is_work_day(day):
        if day.lower() == 'thursday' or day.lower() == 'friday':
            print("Enjoy your weekend")
        else:
            print("Keep working")
    
    @staticmethod
    def is_work_day(day):
        if day.lower() == 'thursday' or day.lower() == 'friday':
            return ("Enjoy your weekend")
        return ("Keep working")

    @classmethod
    def class_method_example(cls):
        print( "This is a class method")
    

    
    

    


# Employee.class_method_example()
employee1 = Employee('Ali','Abdi','SomaliREN',500)
employee2 = Employee('Ahmed','Abdi','SomaliREN',500)
# print(employee1)
# print(employee2)
# # print(employee2.email())
# print(employee2.email)

# employee2.is_work_day('Friday')


class Developer(Employee):

    
    def __init__(self,first_name,last_name,company,pay,pl):
        super().__init__(first_name,last_name,company,pay)
        self.pl = pl 
    # Method overflow
    # def call():
    #     pass
    # def call(var):
    #     pass
    # def call(var1,var2):
    #     pass

    def __repr__(self):
        return f"{self.first_name} {self.last_name} {self.company} {self.pay} {self.pl}"
    
class Manager(Employee):
    raise_up = 3.5



dev1 = Developer("Ali","Hassan",'Somaliren',600,'Python')
dev1.yearly_raise()
m1 = Manager("Ali","Hassan",'Somaliren',600)
m1.yearly_raise()

print(dev1)
print(m1)









# today = datetime.today()
# print(today)




#somalihello

