from datetime import datetime

class Course:
    def __init__(self, id, title, department, credits, instructor, description, created_at):
        self.id = id
        self.title = title
        self.department = department
        self.credits = credits
        self.instructor = instructor
        self.description = description
        self.created_at = created_at

    def to_dict(self):
        return self.__dict__

    @staticmethod
    def from_dict(data):
        return Course(**data)
