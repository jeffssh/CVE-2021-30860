//
//  ContentView.swift
//  poc-app
//
//  Created by Jeffrey Hofmann on 2/27/23.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationView {
            Text("Got Calc?").padding()
        }.onAppear { Clazz.go() }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

func go() {
    //Clazz.go()
}
