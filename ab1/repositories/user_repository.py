from json_storage import load_data, save_data
from models.user import Student

USERS_PATH = 'data/users.json'

def get_students():
    return [Student.from_dict(d) for d in load_data(USERS_PATH)]

def get_student_by_id(student_id):
    return next((s for s in get_students() if s.id == student_id), None)
