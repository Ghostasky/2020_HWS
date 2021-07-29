
def check(a):
	target="YWtmYHxgaGhjWHRzcmN+eg==".decode("base64")
	for i in range(len(a)):
		if chr(ord(a[i])^7)!=target[i]:
			return 0
	return 1

a=raw_input("password:")
if check(a)==1:
	print("ok!")
else:
	print("nope!")
#flag="flag{good_study}"

raw_input()

