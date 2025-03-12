async function reqVcert() {
  // Convert step-by-step
}

def req_v_cert():
    vcert_title = input("Enter the Vcert you want to request : ")
    query = "SELECT * from certifiers;"
    d = fetch_data_all(connection, query)
    depen = []
    req_ip = None
    req_port = None
    for i in d:
        if(i[2] == vcert_title):
            depen = [j for j in i[7]]
            req_ip = i[3]
            req_port = i[4]
            break

    if(req_ip == None):
        print("No such CA registered !")
        return

    vcerts = []
    for i in depen:
        if u.vcert_list.get(i) is not None:
            vcerts.append(u.vcert_list[i])
    ans = u.request_vcert(vcert_title,vcerts, req_ip, req_port)

        //-------------Detail of request_vcert----------------------//
        def request_vcert(self,title,required_vcert, ip ,port):
            s = self.connect_to_CA(ip, port)
            if s is None:
                return
            vcert = {"title":title, "attributes" : None, "commit": None, "signature": None}
            print("Coming to try block")
            prevParams, prevVcerts, prevAttributes = self.updateRequiredVcerts(required_vcert)

                //-------------Detail of updateRequiredVcerts----------------------//
                def updateRequiredVcerts(self,requiredVcerts):
                    prevParams, prevVcerts, prevAttributes = [], [], []
                    for i in range(len(requiredVcerts)):
                        print("This is the required vcerdts")
                        print(requiredVcerts[i])
                        title = requiredVcerts[i]["title"]
                        # path = self.title_to_path(title)
                        schema, params, pk = self.downloadPublicInformation(title)
                        prevParams.append(params)
                        prevVcerts.append((requiredVcerts[i]["commit"], requiredVcerts[i]["signature"]))
                        attributes = []
                        encode_str = []
                        for key in schema:
                            attributes.append(requiredVcerts[i]["attributes"][key])
                            encode_str.append(schema[key]["type"])
                        prevAttributes.append(encode_attributes(attributes, encode_str))

                          //-------------Detail of encode_attributes----------------------//
                          def encode_attributes(attr, encode_str):
                            o = int(curve_order)
                            encoded_attr = []
                            assert len(attr) == len(encode_str), "mismatch in encoding lengths"
                            for i in range(len(attr)):
                              if encode_str[i] == "str":
                                Chash = sha256(attr[i].encode("utf8").strip()).digest()
                                encoded_attr.append(int.from_bytes(Chash, "big") % o)
                              else:
                                encoded_attr.append(attr[i])
                            return encoded_attr
                          //-------------Detail of encode_attributes----------------------//

                    return (prevParams, prevVcerts, prevAttributes)
                //-------------Detail of updateRequiredVcerts----------------------//

            schema, params, pk = self.downloadPublicInformation(title)
            attributes = {}

            val_of_attr = []
            encode_val_of_attr = []
            for key in schema:
                    value = None
                    if key == "msk":
                        value = self.msk
                        val_of_attr.append(self.msk)
                        encode_val_of_attr.append("int")
                    elif key == "r":
                        value = genRandom()
                        val_of_attr.append(value)
                        encode_val_of_attr.append("int")
                    elif schema[key]["type"] == "str":
                        value = input("Enter the attribute \'"+key+"\' of type "+schema[key]["type"]+" : ")
                        val_of_attr.append(value)
                        encode_val_of_attr.append("str")
                    elif schema[key]["type"] == "int":
                        value = int(input("Enter the attribute \'"+key+"\' of type "+schema[key]["type"]+" : "))
                        val_of_attr.append(value)
                        encode_val_of_attr.append("int")
                    elif schema[key]["type"] == "date":
                        str_date = input("Enter the attribute \'"+key+"\' in Y-m-d format : ")
                        _date = datetime.datetime.strptime(str_date,"%Y-%m-%d").date()
                        value = int(_date.strftime('%Y%m%d'))
                        val_of_attr.append(value)
                        encode_val_of_attr.append("date")
                    #if(key !="msk" or key != "r"):
                    attributes.setdefault(key, value)

            encoded_attribute = encode_attributes(val_of_attr, encode_val_of_attr)
            commit = GenCommitment(params, encoded_attribute)

                //-------------Detail of GenCommitment----------------------//
                def GenCommitment(params, encoded_attr):
                  _, g, o, hs = params 
                  Aw = [multiply(hs[i], encoded_attr[i]) for i in range(len(hs))]
                  comm = multiply(g, encoded_attr[len(hs)])
                  for i in range(0, len(Aw)):
                    comm = add(comm, Aw[i])
                  return comm
                //-------------Detail of GenCommitment----------------------//

            prevAttributes.append([self.msk,val_of_attr[-1]])
            print(prevAttributes)
            zkpok = GenZKPoK(params, prevParams, prevVcerts, prevAttributes, commit)

              //-------------Detail of GenZKPoK----------------------//
              def GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, comm):
                _, g, o, hs= params
                total_wm = [[random.randint(2, o) for _ in range(len(all_enc_attr[i]))] for i in range(len(all_enc_attr))]
                for i in range(1, len(total_wm)):
                  total_wm[i][0] = total_wm[0][0]
                Aw = []
                comm_list = []
                for i in range(len(prev_vcerts)):
                  (_, ttp_g, _, ttp_hs) = prev_params[i]
                  tmp = multiply(ttp_g, total_wm[i][-1])
                  for j in range(len(total_wm[i]) - 1):
                    tmp = add(tmp, multiply(ttp_hs[j], total_wm[i][j]))
                  Aw.append(tmp)
                  comm_list.append(prev_vcerts[i][0])
              
                _tmp = multiply(g, total_wm[len(prev_vcerts)][-1])
                _tmp = add(_tmp, multiply(hs[0], total_wm[len(prev_vcerts)][0]))
                Aw.append(_tmp)
                comm_list.append(comm)
              
                element_list = [g] + Aw + comm_list + hs 
                c = toChallenge(element_list) % o
                total_rm = [[(total_wm[i][j] - c*all_enc_attr[i][j]) % o for j in range(len(total_wm[i]))] for i in range(len(total_wm))]
                return (c, total_rm)
              //-------------Detail of GenZKPoK----------------------//

            print(prevVcerts)
            requestJSON = jsonpickle.encode((prevVcerts, attributes, commit, zkpok))
            s.send(requestJSON.encode())
            print("requestjson")
            print(requestJSON)
            issueVcertJSON = s.recv(8192).decode()
            print(issueVcertJSON)
            issueVcert = jsonpickle.decode(issueVcertJSON)
            _commit, signature = issueVcert
            print("This is commit")
            print(_commit)
            if commit != _commit: 
                    print("Request is corrupted.")
            elif VerifyVcerts(params, pk, signature, SHA256(commit)) == True:
                    vcert["attributes"] = attributes
                    vcert["commit"] = commit
                    vcert["signature"] = signature
                    self.vcert_list[title] = vcert
                    print("Vcert recieved sucessfully !")
                    dump_data(os.getcwd()+"/vcerts.pickle", self.vcert_list)
            else:
                    print("Request is corrupted.")
            s.close()
            return vcert
        //-------------Detail of request_vcert----------------------//

    if ans is None:
        return
    print("vcert recieved ", ans)
