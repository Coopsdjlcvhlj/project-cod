from json_storage import load_data, save_data
from models.product import Course
from datetime import datetime
import uuid

PRODUCTS_PATH = 'data/products.json'

def get_courses():
    return [Course.from_dict(d) for d in load_data(PRODUCTS_PATH)]

def get_course_by_id(course_id):
    return next((c for c in get_courses() if c.id == course_id), None)

def add_course(course):
    courses = get_courses()
    courses.append(course)
    save_data(PRODUCTS_PATH, [c.to_dict() for c in courses])
    return course.id

def update_course(course):
    courses = get_courses()
    for i, c in enumerate(courses):
        if c.id == course.id:
            courses[i] = course
            break
    save_data(PRODUCTS_PATH, [c.to_dict() for c in courses])

def delete_course(course_id):
    courses = [c for c in get_courses() if c.id != course_id]
    save_data(PRODUCTS_PATH, [c.to_dict() for c in courses])
