async function reqVcert() {
  // Convert step-by-step
}

// def req_v_cert():
//     vcert_title = input("Enter the Vcert you want to request : ")
//     query = "SELECT * from certifiers;"
//     d = fetch_data_all(connection, query)
//     depen = []
//     req_ip = None
//     req_port = None
//     for i in d:
//         if(i[2] == vcert_title):
//             depen = [j for j in i[7]]
//             req_ip = i[3]
//             req_port = i[4]
//             break

//     if(req_ip == None):
//         print("No such CA registered !")
//         return

//     vcerts = []
//     for i in depen:
//         if u.vcert_list.get(i) is not None:
//             vcerts.append(u.vcert_list[i])
//     ans = u.request_vcert(vcert_title,vcerts, req_ip, req_port)
//     if ans is None:
//         return
//     print("vcert recieved ", ans)
