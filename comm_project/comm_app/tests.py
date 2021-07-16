from django.test import TestCase
from django.contrib.auth.models import User
from comm_app.views import create_user_person, is_correct_email
from django.test import Client
from django.urls import reverse

# Create your tests here.
class UserTestCase(TestCase):
	def setUp(self):
		for i in range(3):
			name = "user" + str(i)
			create_user_person(name, name+"@mail.com", name, name, "")

	def test_users_created(self):
		self.assertEqual(User.objects.all().count(), 3)

	def test_users_have_zero_points(self):
		for u in User.objects.all():
			self.assertEqual(u.person.rating, 0)

	def test_users_have_verification_code(self):
		for u in User.objects.all():
			self.assertNotEqual(u.person.verification_code, "")

	def test_user_confirm_verification_code(self):
		user = User.objects.get(username="user1")
		self.assertNotEqual(user.person.verification_code, "")
		c = Client()
		c.get(reverse("comm_app:confirm_ver_code", kwargs={'vcode':user.person.verification_code}))
		user = User.objects.get(username="user1")
		self.assertEqual(user.person.verification_code, "")

class PointsTestCase(TestCase):
	def setUp(self):
		c = Client()
		for i in range(3):
			name = "user" + str(i)
			create_user_person(name, name+"@mail.com", name, name, "")
			c.post('/login/', {'uname': name, 'pwd': name})
			c.get(reverse("comm_app:generate_code"))
		
		user = User.objects.get(username="user0")
		for i in range(3, 6):
			name = "user" + str(i)
			create_user_person(name, name+"@mail.com", name, name, user.person.invite_code)
			c.post('/login/', {'uname': name, 'pwd': name})
			c.get(reverse("comm_app:generate_code"))
		
		user = User.objects.get(username="user3")
		for i in range(6, 10):
			name = "user" + str(i)
			a = create_user_person(name, name+"@mail.com", name, name, user.person.invite_code)
			c.post('/login/', {'uname': name, 'pwd': name})
			c.get(reverse("comm_app:generate_code"))
		
		user = User.objects.get(username="user6")
		for i in range(10, 12):
			name = "user" + str(i)
			create_user_person(name, name+"@mail.com", name, name, user.person.invite_code)


	def test_user_points(self):
		user = User.objects.get(username="user0")
		self.assertEqual(user.person.rating, 12)
		user = User.objects.get(username="user3")
		self.assertEqual(user.person.rating, 5)
		user = User.objects.get(username="user6")
		self.assertEqual(user.person.rating, 2)

class EmailTestCase(TestCase):

	def test_emails(self):
		self.assertEqual(is_correct_email("mail@mail.com")[0], True)
		self.assertEqual(is_correct_email("m@m.cc")[0], True)
		self.assertEqual(is_correct_email("mail1231_+@mail.com")[0], True)

		self.assertEqual(is_correct_email("mail@com")[0], False)
		self.assertEqual(is_correct_email("@mail.com")[0], False)
		self.assertEqual(is_correct_email("mailmail.com")[0], False)
		self.assertEqual(is_correct_email("m@m.c")[0], False)
		self.assertEqual(is_correct_email("")[0], False)

	def test_email_exist(self):
		name = "user1"
		user = create_user_person(name, name+"@mail.com", name, name, "")
		self.assertEqual(is_correct_email(name+"@mail.com"),(False, 'The given email already exists.'))