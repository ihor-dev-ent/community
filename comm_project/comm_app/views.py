from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.http import JsonResponse
from .models import Person
from django.utils.crypto import get_random_string
from django.urls import reverse

USERS_WITHOUT_ICODE_COUNT = 5
ADMIN_EMAIL = "admin@community.com"

# Create your views here.
def index(request):
	if request.user.is_authenticated:
		return render(request, 'comm_app/index.html')
	else:
		return render(request, 'comm_app/login.html', {"users_count": User.objects.all().count()})

def user_login(request):
	data = {}
	if request.method == 'POST':
		username = request.POST['uname'].strip()
		password = request.POST['pwd'].strip()
		user = authenticate(request, username=username, password=password)
		if user is not None:
			login(request, user)
			return index(request)
		else:
			data['uname'] = username
			messages.add_message(request, messages.WARNING, 'Incorrect login or password!')
	data["users_count"] = User.objects.all().count()
	return render(request, 'comm_app/login.html', data)

def register(request):
	data = {"users_count": User.objects.all().count()}
	if request.method == 'POST':
		if request.is_ajax():
			# check that user with this invite code exist
			icode = request.POST["icode"].strip()
			if icode:
				try:
					person = Person.objects.get(invite_code=icode)
					data["invite_code"] = icode
				except Person.DoesNotExist:
					data["wrong_code"] = True
			else:
				data["wrong_code"] = True
			return JsonResponse(data)
		else:
			user, err_messages = create_user_person(request.POST['uname'].strip(), request.POST['email'].strip(),
									request.POST['pwd'].strip(), request.POST['chk_pwd'].strip(), request.POST['icode'].strip())
			if user:
				login(request, user)
				send_verification_code_to_user(user, request) # email verification
				messages.add_message(request, messages.SUCCESS, 'Confirm code has been sent to your email address.')
				return index(request)
			else:
				data['uname'] = request.POST['uname'].strip()
				data['email'] = request.POST['email'].strip()
				data['icode'] = request.POST['icode'].strip()
				for msg in err_messages:
					messages.add_message(request, msg['type'], msg['text'])
	return render(request, 'comm_app/login.html', data)

def skip_invite_code(request):
	"""Check for skiping invite code"""
	if request.is_ajax():
		if User.objects.all().count() < USERS_WITHOUT_ICODE_COUNT:
			return JsonResponse({"skip": True})
		return None
	else:
		return index(request)

def confirm_code(request):
	"""Confirm email by verification code"""
	if request.method == 'POST':
		user = request.user
		if user.person.verification_code == request.POST['verification_code'].strip():
			user.person.verification_code = ""
			user.save()
		else:
			messages.add_message(request, messages.WARNING, 'Wrong verification code.')
	elif request.is_ajax():
		return send_code(request)
	return render(request, 'comm_app/index.html')

def confirm_verification_code(request, vcode=""):
	"""Confirm email by verification link"""
	if vcode:
		try:
			p = Person.objects.get(verification_code=vcode)
			p.verification_code = ""
			p.save()
		except:
			messages.add_message(request, messages.WARNING, 'Verification code is outdated.')
	return render(request, 'comm_app/index.html')

def send_code(request):
	"""Send verification code"""
	if request.is_ajax():
		if not request.user.is_anonymous:
			request.user.person.verification_code = get_random_string(20)
			request.user.save()
			send_verification_code_to_user(request.user, request)
			return JsonResponse({"sended": True})
		elif request.user.is_anonymous:
			return JsonResponse({"anonymous": True})
		else:
			return JsonResponse({"bad_request": True})
	else:
		return index(request)

def user_logout(request):
	logout(request)
	return redirect('comm_app:login')

def edit_profile(request):
	if request.method == 'POST':
		user_edited = False
		is_err = False
		email = request.POST['email'].strip()
		pwd = request.POST['pwd'].strip()
		if request.user.email != email:
			chk_email = is_correct_email(email)
			if chk_email[0]:
				request.user.email = email
				request.user.person.verification_code = get_random_string(20)
				user_edited = True
			else:
				is_err = True
				messages.add_message(request, messages.WARNING, chk_email[1])
		if pwd:
			if pwd == request.POST['chk_pwd'].strip():
				request.user.set_password(pwd)
				user_edited = True
			else:
				is_err = True
				messages.add_message(request, messages.WARNING, 'Password mismatch.')
		if is_err == False:
			if user_edited == True:
				request.user.save()
				login(request, request.user)
			return render(request, 'comm_app/index.html')
	return render(request, 'comm_app/login.html', {"users_count": User.objects.all().count()})

def password_reset(request):
	if request.method == 'POST':
		try:
			u = User.objects.get(email=request.POST["email"].strip())
			new_pass = get_random_string(10)
			u.set_password(new_pass)
			u.save()
			send_mail(
						'COMMUNITY reset password',
						'your new password is ' + new_pass,
						ADMIN_EMAIL,
						[u.email],
						fail_silently=False,
					)
			messages.add_message(request, messages.SUCCESS, 'A new password has been sent to your email address.')
			return render(request, 'comm_app/login.html', {"users_count": User.objects.all().count()})
		except User.DoesNotExist:
			messages.add_message(request, messages.WARNING, 'User not found!')
	return render(request, 'comm_app/login.html', {"users_count": User.objects.all().count(), 'password_reset': True})

def generate_invite_code(request):
	p = Person.objects.get(user=request.user)
	if p.invite_code == "":
		icode = get_random_string(20)
		p.invite_code = icode
		p.save()
	else:
		icode = p.invite_code
	return JsonResponse({"icode": icode})

def top_ten_users(request):
	data = {"top_users": []}
	persons = Person.objects.all().order_by('-rating')[:10]
	for p in persons:
		data["top_users"].append([p.user.username, p.rating])
	return render(request, 'comm_app/top_users.html', data)

# SERVICE CODE #

def send_verification_code_to_user(user, request):
	send_mail(
			'COMMUNITY confirm email',
			'Your confirm code is ' + user.person.verification_code +
			    '. Enter the code on the website or follow the link ' +
			    request.build_absolute_uri((reverse("comm_app:confirm_ver_code", kwargs={'vcode':user.person.verification_code}))),
			ADMIN_EMAIL,
			[user.email],
			fail_silently=False,
		)

def create_user_person(uname, email, pwd, chk_pwd, icode):
	err_person, err_messages = check_person_data_err(uname, email, pwd, chk_pwd, icode)
	if err_person:
		return (None, err_messages)
	inviter = None
	if icode != "":
		inviter = get_inviter(icode)
		if not inviter:
			return (None, [{'type': messages.WARNING, 'text': 'Wrong invite code.'}])
	
	user = User.objects.create_user(uname, email, pwd)
	user.person.inviter = inviter
	user.person.verification_code = get_random_string(20)

	user.save()

	if inviter:
		distribute_points(inviter)

	return (user, [])

def distribute_points(person):
	"""Increase the rating of inviters"""
	points = person.invited_persons.all().count()
	while points > 0:
		if person.inviter:
			person.rating += 1
			points -= 1
			person.save()
			person = person.inviter
		else:
			person.rating += points
			person.save()
			points = 0

def get_inviter(icode):
	try:
		return Person.objects.get(invite_code=icode)
	except Person.DoesNotExist:
		return None

def check_person_data_err(uname, email, pwd, chk_pwd, icode):
	is_err = False
	err_messages = []
	if uname != None:
		try:
			User.objects.get(username=uname)
			err_messages.append({'type': messages.WARNING, 'text': 'The given name already exists.'})
			is_err = True
		except User.DoesNotExist:
			pass
	if email != None:
		chk_email = is_correct_email(email)
		if not chk_email[0]:
			err_messages.append({'type': messages.WARNING, 'text': chk_email[1]})
			is_err = True
	if pwd != None:
		if pwd != chk_pwd:
			err_messages.append({'type': messages.WARNING, 'text': 'Password mismatch.'})
			is_err = True

	if icode == "":
		if User.objects.all().count() > USERS_WITHOUT_ICODE_COUNT:
			err_messages.append({'type': messages.WARNING, 'text': 'Need invite code to register.'})
			is_err = True
	
	return (is_err, err_messages)

def is_correct_email(email):
	import re
	regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
	if(re.match(regex, email)):
		try:
			User.objects.get(email=email)
			return (False, 'The given email already exists.')
		except User.DoesNotExist:
			return (True, '')
	return (False, 'Incorrect email.')

# SERVICE CODE #