from datetime import datetime

class Student:
    def __init__(self, id, name, group, year, enrolled_at, email, is_active):
        self.id = id
        self.name = name
        self.group = group
        self.year = year
        self.enrolled_at = enrolled_at
        self.email = email
        self.is_active = is_active

    def to_dict(self):
        return self.__dict__

    @staticmethod
    def from_dict(data):
        return Student(**data)
