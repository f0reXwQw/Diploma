import binascii
import datetime
import argparse
import hashlib
import os

def generate_key():
	return binascii.hexlify(os.urandom(16))

def generate_SSN(file_name):
	with open(file_name,'rb') as file:
		file_content = file.read()
	file_md5 = hashlib.md5(file_content).hexdigest()
	curr_dt = datetime.datetime.now()
	dt_md5 = hashlib.md5(str(curr_dt).encode()).hexdigest()
	return hashlib.md5((file_md5 + dt_md5).encode()).hexdigest()


if __name__ == "__main__":

	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--file', type=str, default=None, help='The name of the file to be packaged')
	parser.add_argument('-k', '--key', type=str, default=None, help='AES-128 key')
	parser.add_argument('-s', '--ssn', type=str, default=None, help='Serial software number')
	args = parser.parse_args()

	assert args.file is not None
	if args.file:
		if not os.path.exists(args.file):
			raise ValueError('Input file {0} is missing'.format(args.file))

	if args.key:
		key = args.key
	else:
		key = generate_key();

	if args.ssn:
		ssn = args.ssn;
	else:
		ssn = generate_SSN(args.file)

	os.system("./packer {0} {1} {2}".format(args.file, key, ssn))