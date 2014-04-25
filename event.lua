local event = {} 

local event_connector = {} 

function event_connector:connect(func)
	if not self.flist then 
		self.flist = {}
	end 
	table.insert(self.flist, func)
end 

function event_connector:fire(...)
	for _, func in pairs(self.flist) do 
		func(...)
	end 
end 

function event.create() 
	return setmetatable({}, {__index = event_connector})
end 

return event 