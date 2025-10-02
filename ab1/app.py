import sys
import uuid
from datetime import datetime
from repositories.user_repository import get_students as fetch_students, get_student_by_id as fetch_student_by_id
from repositories.product_repository import (
    get_courses as fetch_courses, get_course_by_id as fetch_course_by_id,
    add_course as insert_course, update_course as modify_course, delete_course as remove_course
)
from models.product import Course
from models.user import Student
from tabulate import tabulate

# Команди для взаємодії з додатком:
#   add/student              - створити нового студента
#   list/students            - показати список студентів
#   show/student/<id>        - показати інформацію про студента
#   add/course               - створити новий курс
#   list/courses             - показати всі курси
#   show/course/<id>         - показати курс
#   edit/course/<id>         - змінити курс
#   remove/course/<id>       - видалити курс
#   quit                     - завершити роботу

def run():
    while True:
        cmd = input(">>> ").strip()
        if cmd == 'quit':
            break

        elif cmd == 'list/students':
            all_students = fetch_students()
            rows = [[st.id, st.name, st.group, st.year] for st in all_students]
            print(tabulate(rows, headers=["ID", "Name", "Group", "Year"], tablefmt="github"))

        elif cmd.startswith('show/student/'):
            sid = cmd.split('/')[-1]
            st = fetch_student_by_id(sid)
            if st is not None:
                for k, v in st.to_dict().items():
                    print(f"{k}: {v}")
            else:
                print("No such student.")

        elif cmd == 'list/courses':
            all_courses = fetch_courses()
            rows = [[crs.id, crs.title, crs.department, crs.credits] for crs in all_courses]
            print(tabulate(rows, headers=["ID", "Title", "Department", "Credits"], tablefmt="fancy_grid"))

        elif cmd.startswith('show/course/'):
            cid = cmd.split('/')[-1]
            crs = fetch_course_by_id(cid)
            if crs:
                for k, v in crs.to_dict().items():
                    print(f"{k}: {v}")
            else:
                print("Course not found.")

        elif cmd.startswith('remove/course/'):
            cid = cmd.split('/')[-1]
            remove_course(cid)
            print("Course was removed (if present).")

        elif cmd.startswith('edit/course/'):
            cid = cmd.split('/')[-1]
            crs = fetch_course_by_id(cid)
            if not crs:
                print("No such course.")
                continue
            crs.title = input("New title: ")
            crs.department = input("New department: ")
            try:
                crs.credits = int(input("New credits: "))
            except Exception:
                print("Invalid credits, set to 0.")
                crs.credits = 0
            crs.instructor = input("New instructor: ")
            crs.description = input("New description: ")
            crs.created_at = datetime.now().isoformat()
            modify_course(crs)
            print("Course updated.")

        elif cmd == 'add/course':
            new_course = Course(
                id=str(uuid.uuid4()),
                title=input("Title: "),
                department=input("Department: "),
                credits=int(input("Credits: ")),
                instructor=input("Instructor: "),
                description=input("Description: "),
                created_at=datetime.now().isoformat()
            )
            insert_course(new_course)
            print("Course created.")

        elif cmd == 'add/student':
            new_student = Student(
                id=str(uuid.uuid4()),
                name=input("Name: "),
                group=input("Group: "),
                year=int(input("Year: ")),
                enrolled_at=datetime.now().isoformat(),
                email=input("Email: "),
                is_active=True
            )
            # Додаємо студента
            students = fetch_students()
            students.append(new_student)
            # Зберігаємо
            from json_storage import save_data
            save_data('data/users.json', [s.to_dict() for s in students])
            print("Student created.")

        else:
            print("Unknown command. Try again.")

if __name__ == '__main__':
    run()
