


# !Create job boarding application
# Write a job boarding application that has the following Requirements
# TODO1. Prompts [name: ] = input
# TODO2. Prompts [Years of experience]
# for example users enters 4 
# clas openingpositions: name, location , years of e
# TODO3: Show the user opening jobs to apply
# opening jobs will be displayed according the users experience
# opening jobs will have name, location, years of experience fields
# so if the user's input value [years of experience] is greater or equal to any of the opening jobs experience field 

from dataclasses import dataclass
from typing import List




# @dataclass
# class Department:
#     name:str
@dataclass
class OpeningPositions:
    name: str
    location:str
    experience:str

    def __repr__(self):
        return f'{self.name} {self.location} {self.experience}'

@dataclass
class Benefits:
    name:str
    description:str = None

    def __repr__(self):
        return f"{self.name}"

@dataclass
class Projects:
    name:str
    location:str

    def __repr__(self):
        return f"{self.name}, {self.location}"


@dataclass
class Applicant:
    name:str
    years_of_exp:int
@dataclass
class Company:
    name:str
    opening_positions: List[OpeningPositions]
    benefits: List[Benefits]
    projects:List[Projects]

    def invite(self,you):
        # Benefits
        print(f"{you} welcome to {self.name}")
        for indx, benefit in enumerate(self.benefits, start=1):
            print(f"{indx}. {benefit}")
        
        # Projects
        for indx, project in enumerate(self.projects,start=1):
            print(f"{indx}. {project}")
    
    def opening_p(self,experience):
        for indx, job in enumerate(self.opening_positions):
            if self.opening_positions[indx].experience <= experience :
                print(f"{indx}. {job}")

        

# Department = [
#     Department("Network Engineer","Business Developer")
# ]
POSITIONS = [
    OpeningPositions("Network Engineer","Hodan District",5),
    OpeningPositions("Business Developer","Wadajir District",7),
    OpeningPositions("System Engineer","Hodan District",15)
]

# print(len(POSITIONS))


BENEFITS = [
    Benefits("Remote Work"),
    Benefits("Free Lunch"),
    Benefits("Free Travel"),
]

PROJECTS = [
    Projects("Network Setup","Mogadishu"),
    Projects("System Setup","Waberi"),
]

# TODO 1. Company information setup

def apply_job():
    try:
     
        you = input("Your Name: ")
        experience = int(input("Years of experience: "))
        applicant = Applicant(name=you,years_of_exp=experience)
        somaliREN = Company("SomaliREN",opening_positions=POSITIONS,benefits=BENEFITS,projects=PROJECTS) 
        somaliREN.opening_p(applicant.years_of_exp) # List of opening positions
        user_input = int(input('Select Position you would like to apply: '))
        if not user_input in range(0,len(POSITIONS)):
            return "Incorrect value"
    
        select_position = POSITIONS[user_input]
        if applicant.years_of_exp >= select_position.experience:
            return somaliREN.invite(applicant.name)
        return "Sorry!, You are not qualified for this job"     
    except ValueError:
        print("Wrong Command")
    
print(apply_job())




class GoogleMeet:
    def __init__(self,name):
        pass












