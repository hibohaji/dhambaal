

class OpeningPositions:
    def __init__(self,name,location,min_exp):
        self.name = name
        self.location = location
        self.min_exp = min_exp

    def __str__(self):
        return f"{self.name} in {self.location} requires atleast ({self.min_exp} years) of experience"


class Applicant:
    def __init__(self,name,years_of_experience):
        self.name = name
        self.years_of_experience = years_of_experience
    
    def __repr__(self):
        return self.name

class Benefits:
    def __init__(self,description):
        self.description = description
    def __repr__(self):
        return self.description

class Projects:
    def __init__(self,name,location):
        self.name = name
        self.location = location
    
    def __repr__(self):
        return f"{self.name}, {self.location}"


class Company:
    def __init__(self,name,benefits:list[Benefits],projects:list[Projects],opening_jobs:list[OpeningPositions]):
        self.name = name
        self.beneifts = benefits
        self.projects = projects
        self.opening_jobs = opening_jobs
    
    def invite(self,applicant,title):
        
        print(f"\nWelcome to {self.name} {applicant} Here are the list of projects you will work on as {title}")
        print('***'*35)
        for index, project in enumerate(self.projects, start=1):
            print(f"{index}. {project}")
        
        print("\nHere are the benefits you will get working with us")
        for index, benefit in enumerate(self.beneifts,start=1 ):
            print(f"{index}. {benefit}")
    
    def opening_positions(self):
        print(f"\n Here the list of opening jobs at {self.name}")
        for i, positions in enumerate( self.opening_jobs, start=1):
            print(f"{i}. {positions}")

         

OPENING_POSITIONS = [
    OpeningPositions(name="Network Engineer",location="Mogadishu",min_exp=5),
    OpeningPositions(name= "Systems Engineer",location="Mogadishu",min_exp=4),
    OpeningPositions(name= "Software Engineer",location="Mogadishu",min_exp=3),
]

PROJECTS = [
    Projects("Configuring SSL for Asal Solutions",'Mogadishu'),
    Projects("Creating Network Environment for Univerties",'Mogadishu'),
    Projects("Configuring SSL for Asal Solutions",'Hargeisa'),
    Projects("Creating Network Environment for Univerties",'Lasanod'),
    Projects("Configuring SSL for Asal Solutions",'Marka'),
    Projects("Creating Network Environment for Univerties",'Jigjiga')
]

BENEFITS = [
    Benefits("Remote Work is allowed"),
    Benefits("Free Lunch :) ")
]


def apply_job():

    try:    
        MIN_EXP = 3
        name = input("fadlan gali magacaaga koobaad: ")
        years_of_experience = int(input("Fadlan gali khibradaada shaqo: "))
        applicant = Applicant(name,years_of_experience)
        somaliREN = Company(name="somaliREN",projects=PROJECTS,benefits=BENEFITS,opening_jobs=OPENING_POSITIONS)
        # Show the applicant oppening positions
        somaliREN.opening_positions()
        user_input = int(input("\nWhich Job would you like to apply please select by number: "))
        if not user_input in range(1,len(OPENING_POSITIONS)+1):
            return ("Wax khaldan baad galisay")
    
        selected_position = OPENING_POSITIONS[user_input-1]
        if applicant.years_of_experience >= selected_position.min_exp:
            return somaliREN.invite(applicant,selected_position.name)
        
        return ("Waan Ka xunahay ma aadan buuxinin shuruudihii shaqada")
        
    except ValueError:
        return ("Wax khaldan baad galisay ....")



if __name__ == '__main__':
  job = apply_job()
  print(job)
