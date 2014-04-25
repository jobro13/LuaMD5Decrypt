local bit = require "bit"
local color = require "color"
local event = require "event"

local function imod(i,mod)
	return i % mod 
end 

local gsub = string.gsub 
local strlen = string.len
local strsub = string.sub 
local getn = table.getn 
local strbyte = string.byte 
local tremove = table.remove 
local bor = bit.bor 
local bxor = bit.bxor 
local lshift = bit.blshift 
local rshift = bit.brshift
local band = bit.band
local tinsert = table.insert
local strchar = string.char
local format = string.format 
local clock = os.clock 
local strrep = string.rep

-- An MD5 mplementation in Lua, requires bitlib
-- 10/02/2001 jcw@equi4.com

md5={ff=tonumber('ffffffff',16),consts={}}

gsub([[ d76aa478 e8c7b756 242070db c1bdceee
	f57c0faf 4787c62a a8304613 fd469501
	698098d8 8b44f7af ffff5bb1 895cd7be
	6b901122 fd987193 a679438e 49b40821
	f61e2562 c040b340 265e5a51 e9b6c7aa
	d62f105d 02441453 d8a1e681 e7d3fbc8
	21e1cde6 c33707d6 f4d50d87 455a14ed
	a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
	fffa3942 8771f681 6d9d6122 fde5380c
	a4beea44 4bdecfa9 f6bb4b60 bebfbc70
	289b7ec6 eaa127fa d4ef3085 04881d05
	d9d4d039 e6db99e5 1fa27cf8 c4ac5665
	f4292244 432aff97 ab9423a7 fc93a039
	655b59c3 8f0ccc92 ffeff47d 85845dd1
	6fa87e4f fe2ce6e0 a3014314 4e0811a1
	f7537e82 bd3af235 2ad7d2bb eb86d391
	67452301 efcdab89 98badcfe 10325476 ]],
  '(%w+)', function (s) tinsert(md5.consts,tonumber(s,16)) end)

function md5.state_tostr(a,b,c,d)
	local swap=function (w) return beInt(leIstr(w)) end
	return format("%08x%08x%08x%08x",swap(a),swap(b),swap(c),swap(d))
end

function md5.transform(A,B,C,D)
  local f=function (x,y,z) return bor(band(x,y),band(-x-1,z)) end
  local g=function (x,y,z) return bor(band(x,z),band(y,-z-1)) end
  local h=function (x,y,z) return bxor(x,bxor(y,z)) end
  local i=function (x,y,z) return bxor(y,bor(x,-z-1)) end
  local op = 0
  local z=function (f,a,b,c,d,x,s,ac, POSH)
 		local a = (a % ( 2^32))
 		md5.beginOp:fire(f,a,b,c,d,x,s,ac,POSH)
  	    a=band(a+f(b,c,d)+x+ac,md5.ff)
	    -- be *very* careful that left shift does not cause rounding!

      md5.midOp:fire(f,a,b,c,d,x,s,ac,POSH)
      local ret = bor(lshift(band(a,rshift(md5.ff,s)),s),rshift(a,32-s))+b
	   	ret = ret % (2^32)
	   	md5.endOp:fire(f,ret,b,c,d,x,s,ac,POSH)
	    return ret 
	  end
  local a,b,c,d=A,B,C,D
  local t=md5.consts
  a=z(f,a,b,c,d,X[ 0], 7,t[ 1],1)
  d=z(f,d,a,b,c,X[ 1],12,t[ 2],4)
  c=z(f,c,d,a,b,X[ 2],17,t[ 3],3)
  b=z(f,b,c,d,a,X[ 3],22,t[ 4],2)
  a=z(f,a,b,c,d,X[ 4], 7,t[ 5],1)
  d=z(f,d,a,b,c,X[ 5],12,t[ 6],4)
  c=z(f,c,d,a,b,X[ 6],17,t[ 7],3)
  b=z(f,b,c,d,a,X[ 7],22,t[ 8],2)
  a=z(f,a,b,c,d,X[ 8], 7,t[ 9],1)
  d=z(f,d,a,b,c,X[ 9],12,t[10],4)
  c=z(f,c,d,a,b,X[10],17,t[11],3)
  b=z(f,b,c,d,a,X[11],22,t[12],2)
  a=z(f,a,b,c,d,X[12], 7,t[13],1)
  d=z(f,d,a,b,c,X[13],12,t[14],4)
  c=z(f,c,d,a,b,X[14],17,t[15],3)
  b=z(f,b,c,d,a,X[15],22,t[16],2)

  a=z(g,a,b,c,d,X[ 1], 5,t[17],1)
  d=z(g,d,a,b,c,X[ 6], 9,t[18],4)
  c=z(g,c,d,a,b,X[11],14,t[19],3)
  b=z(g,b,c,d,a,X[ 0],20,t[20],2)
  a=z(g,a,b,c,d,X[ 5], 5,t[21],1)
  d=z(g,d,a,b,c,X[10], 9,t[22],4)
  c=z(g,c,d,a,b,X[15],14,t[23],3)
  b=z(g,b,c,d,a,X[ 4],20,t[24],2)
  a=z(g,a,b,c,d,X[ 9], 5,t[25],1)
  d=z(g,d,a,b,c,X[14], 9,t[26],4)
  c=z(g,c,d,a,b,X[ 3],14,t[27],3)
  b=z(g,b,c,d,a,X[ 8],20,t[28],2)
  a=z(g,a,b,c,d,X[13], 5,t[29],1)
  d=z(g,d,a,b,c,X[ 2], 9,t[30],4)
  c=z(g,c,d,a,b,X[ 7],14,t[31],3)
  b=z(g,b,c,d,a,X[12],20,t[32],2)

  a=z(h,a,b,c,d,X[ 5], 4,t[33],1)
  d=z(h,d,a,b,c,X[ 8],11,t[34],4)
  c=z(h,c,d,a,b,X[11],16,t[35],3)
  b=z(h,b,c,d,a,X[14],23,t[36],2)
  a=z(h,a,b,c,d,X[ 1], 4,t[37],1)
  d=z(h,d,a,b,c,X[ 4],11,t[38],4)
  c=z(h,c,d,a,b,X[ 7],16,t[39],3)
  b=z(h,b,c,d,a,X[10],23,t[40],2)
  a=z(h,a,b,c,d,X[13], 4,t[41],1)
  d=z(h,d,a,b,c,X[ 0],11,t[42],4)
  c=z(h,c,d,a,b,X[ 3],16,t[43],3)
  b=z(h,b,c,d,a,X[ 6],23,t[44],2)
  a=z(h,a,b,c,d,X[ 9], 4,t[45],1)
  d=z(h,d,a,b,c,X[12],11,t[46],4)
  c=z(h,c,d,a,b,X[15],16,t[47],3)
  b=z(h,b,c,d,a,X[ 2],23,t[48],2)

  a=z(i,a,b,c,d,X[ 0], 6,t[49],1)
  d=z(i,d,a,b,c,X[ 7],10,t[50],4)
  c=z(i,c,d,a,b,X[14],15,t[51],3)
  b=z(i,b,c,d,a,X[ 5],21,t[52],2)
  a=z(i,a,b,c,d,X[12], 6,t[53],1)
  d=z(i,d,a,b,c,X[ 3],10,t[54],4)
  c=z(i,c,d,a,b,X[10],15,t[55],3)
  b=z(i,b,c,d,a,X[ 1],21,t[56],2)
  a=z(i,a,b,c,d,X[ 8], 6,t[57],1)
  d=z(i,d,a,b,c,X[15],10,t[58],4)
  c=z(i,c,d,a,b,X[ 6],15,t[59],3)
  b=z(i,b,c,d,a,X[13],21,t[60],2)
  a=z(i,a,b,c,d,X[ 4], 6,t[61],1)
  d=z(i,d,a,b,c,X[11],10,t[62],4)
  c=z(i,c,d,a,b,X[ 2],15,t[63],3)
  b=z(i,b,c,d,a,X[ 9],21,t[64],2)
  md5.endBlock:fire(a,b,c,d,A,B,C,D)
  return A+a,B+b,C+c,D+d
end

function md5.Calc(s)
	GLOBAL_RESULTS = {Same = {}, NSame = {}}
  local msgLen=strlen(s)
  local padLen=56-imod(msgLen,64)
  if imod(msgLen,64)>56 then padLen=padLen+64 end
  if padLen==0 then padLen=64 end
  s=s..strchar(128)..strrep(strchar(0),padLen-1)
  s=s..leIstr(8*msgLen)..leIstr(0)
  assert(imod(strlen(s),64)==0)
  local t=md5.consts
  local a,b,c,d=t[65],t[66],t[67],t[68]
  for i=1,strlen(s),64 do
    X=leStrCuts(strsub(s,i,i+63),4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4)
    assert(getn(X)==16)
    X[0]=tremove(X,1) -- zero based!
    a,b,c,d=md5.transform(a,b,c,d)
  end
  local swap=function (w) return beInt(leIstr(w)) end

  local output =  format("%08x%08x%08x%08x",swap(a),swap(b),swap(c),swap(d))
  return output
end


-- convert little-endian 32-bit int to a 4-char string
function leIstr(i)
  local f=function (s) return strchar(band(rshift(i,s),255)) end
  return f(0)..f(8)..f(16)..f(24)
end

do -- from util.lua
  -- convert raw string to big-endian int
  function beInt(s)
    local v=0
    for i=1,strlen(s) do v=v*256+strbyte(s,i) end
    return v
  end
  -- convert raw string to little-endian int
  function leInt(s)
    local v=0
    for i=strlen(s),1,-1 do v=v*256+strbyte(s,i) end
    return v
  end
  -- cut up a string in little-endian ints of given size
  function leStrCuts(s,...)
    local o,r=1,{}
    for i=1,getn(arg) do
      tinsert(r,leInt(strsub(s,o,o+arg[i]-1)))
      o=o+arg[i]
    end
    return r
  end
end

md5.beginOp = event.create()
md5.endOp = event.create()
md5.endBlock = event.create()
md5.midOp = event.create()

return md5